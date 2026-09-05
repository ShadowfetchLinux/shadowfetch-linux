#!/usr/bin/env bash
set -euo pipefail

root=${QA_ROOT:-/home/rtx5060ti/projects/shadowfetch-4.0.0}
qa_root="$root/work/qa-4.0.0"
qga_exec="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/qga_exec.py"
iso=${QA_ISO:-"$root/shadowfetch-4.0.0-amd64.iso"}

usage() {
    cat >&2 <<'EOF'
usage:
  vm_harness.sh create NAME FIRMWARE VNC_DISPLAY DISK_GIB
  vm_harness.sh clone NAME FIRMWARE VNC_DISPLAY SOURCE_DISK
  vm_harness.sh boot-live NAME
  vm_harness.sh boot-installed NAME
  vm_harness.sh wait-qga NAME [SECONDS]
  vm_harness.sh exec NAME COMMAND [TIMEOUT]
  vm_harness.sh exec-detach NAME COMMAND
  vm_harness.sh resume NAME GUEST_PID [OBSERVATION_SECONDS]
  vm_harness.sh capture NAME OUTPUT.png
  vm_harness.sh monitor NAME COMMAND
  vm_harness.sh stop NAME

FIRMWARE is bios or uefi. VNC_DISPLAY is the QEMU display number, for example
35 for 127.0.0.1:5935. Every VM is private to loopback and uses KVM.
EOF
    exit 2
}

require_name() {
    [[ ${1:-} =~ ^[a-z0-9][a-z0-9-]*$ ]] || {
        echo "invalid VM name: ${1:-}" >&2
        exit 2
    }
}

vm_dir() {
    require_name "$1"
    printf '%s/vm/%s' "$qa_root" "$1"
}

read_meta() {
    local dir
    dir=$(vm_dir "$1")
    [[ -r "$dir/meta.env" ]] || {
        echo "missing VM metadata: $dir/meta.env" >&2
        exit 1
    }
    # The file is generated from validated values by this script.
    # shellcheck source=/dev/null
    source "$dir/meta.env"
}

pid_is_live() {
    local dir pid
    dir=$(vm_dir "$1")
    [[ -r "$dir/qemu.pid" ]] || return 1
    read -r pid <"$dir/qemu.pid"
    [[ $pid =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null && [[ -r /proc/$pid/cmdline ]] && tr "\0" " " <"/proc/$pid/cmdline" | grep -Fq -- "$dir/disk.qcow2"
}

create_vm() {
    local name=$1 firmware=$2 display=$3 disk_gib=$4 dir
    require_name "$name"
    [[ $firmware == bios || $firmware == uefi ]] || usage
    [[ $display =~ ^[0-9]+$ ]] || usage
    [[ $disk_gib =~ ^[0-9]+$ ]] || usage
    dir=$(vm_dir "$name")
    [[ ! -e "$dir/disk.qcow2" ]] || {
        echo "refusing to replace existing disk: $dir/disk.qcow2" >&2
        exit 1
    }
    mkdir -p "$dir"
    qemu-img create -f qcow2 "$dir/disk.qcow2" "${disk_gib}G" >/dev/null
    printf 'firmware=%q\nvnc_display=%q\n' "$firmware" "$display" >"$dir/meta.env"
}

clone_vm() {
    local name=$1 firmware=$2 display=$3 source_disk=$4 dir
    require_name "$name"
    [[ $firmware == bios || $firmware == uefi ]] || usage
    [[ $display =~ ^[0-9]+$ ]] || usage
    [[ -f $source_disk ]] || {
        echo "source disk not found: $source_disk" >&2
        exit 1
    }
    dir=$(vm_dir "$name")
    [[ ! -e "$dir/disk.qcow2" ]] || {
        echo "refusing to replace existing disk: $dir/disk.qcow2" >&2
        exit 1
    }
    mkdir -p "$dir"
    qemu-img create -f qcow2 -F qcow2 -b "$source_disk" "$dir/disk.qcow2" >/dev/null
    printf 'firmware=%q\nvnc_display=%q\n' "$firmware" "$display" >"$dir/meta.env"
}

boot_vm() {
    local name=$1 medium=$2 dir firmware vnc_display vga_device
    require_name "$name"
    read_meta "$name"
    dir=$(vm_dir "$name")
    pid_is_live "$name" && {
        echo "VM is already running: $name" >&2
        exit 1
    }
    rm -f "$dir/qga.sock" "$dir/hmp.sock" "$dir/qemu.pid"

    local -a firmware_args medium_args vga_args
    firmware_args=()
    if [[ $firmware == uefi ]]; then
        [[ -r /usr/share/OVMF/OVMF_CODE_4M.fd && -r /usr/share/OVMF/OVMF_VARS_4M.fd ]] || {
            echo "OVMF 4M firmware files are unavailable" >&2
            exit 1
        }
        [[ -e "$dir/OVMF_VARS_4M.fd" ]] || cp /usr/share/OVMF/OVMF_VARS_4M.fd "$dir/OVMF_VARS_4M.fd"
        firmware_args=(
            -drive "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd"
            -drive "if=pflash,format=raw,file=$dir/OVMF_VARS_4M.fd"
        )
    fi

    medium_args=()
    if [[ $medium == live ]]; then
        [[ -f $iso ]] || {
            echo "ISO not found: $iso" >&2
            exit 1
        }
        medium_args=(-drive "file=$iso,media=cdrom,readonly=on" -boot "order=d,menu=on")
    else
        medium_args=(-boot "order=c,menu=on")
    fi

    # QXL avoids the observed virtio 1366px framebuffer stride corruption.
    # Explicit virtio use is supported; prefer 1920x1080 for that QA adapter.
    vga_device=${QA_VGA_DEVICE:-qxl-vga}
    [[ $vga_device == virtio-vga || $vga_device == VGA || $vga_device == qxl-vga ]] || {
        echo "QA_VGA_DEVICE must be virtio-vga, VGA, or qxl-vga" >&2
        exit 2
    }
    vga_args=(-device "$vga_device")
    if [[ -n ${QA_XRES:-} || -n ${QA_YRES:-} ]]; then
        [[ ${QA_XRES:-} =~ ^[0-9]+$ && ${QA_YRES:-} =~ ^[0-9]+$ ]] || {
            echo "QA_XRES and QA_YRES must both be positive integers" >&2
            exit 2
        }
        vga_args=(-device "$vga_device,xres=$QA_XRES,yres=$QA_YRES")
    fi

    qemu-system-x86_64 \
        -name "shadowfetch-4.0.0-$name" \
        -enable-kvm -machine q35,accel=kvm -cpu host -smp "${QA_CPUS:-4}" -m "${QA_MEMORY_MB:-8192}" \
        "${firmware_args[@]}" \
        -drive file="$dir/disk.qcow2",format=qcow2,if=virtio,cache=writeback,discard=unmap \
        "${medium_args[@]}" \
        "${vga_args[@]}" \
        -device qemu-xhci -device usb-tablet \
        -device intel-hda -device hda-duplex \
        -display none -vnc "127.0.0.1:$vnc_display" \
        -device virtio-serial-pci \
        -chardev socket,path="$dir/qga.sock",server=on,wait=off,id=qga0 \
        -device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0 \
        -monitor unix:"$dir/hmp.sock",server=on,wait=off \
        -serial file:"$dir/serial.log" \
        -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
        -daemonize -pidfile "$dir/qemu.pid"
    printf 'started %s (%s, VNC 127.0.0.1:59%02d)\n' "$name" "$firmware" "$vnc_display"
}

wait_qga() {
    local name=$1 timeout=${2:-360} dir deadline
    dir=$(vm_dir "$name")
    deadline=$((SECONDS + timeout))
    while ((SECONDS < deadline)); do
        if [[ -S "$dir/qga.sock" ]] && "$qga_exec" "$dir/qga.sock" 'true' --timeout 5 >/dev/null 2>&1; then
            echo "QGA_READY"
            return 0
        fi
        sleep 2
    done
    echo "timed out waiting for guest agent: $name" >&2
    return 1
}

capture_vm() {
    local name=$1 output=$2 dir ppm
    read_meta "$name"
    dir=$(vm_dir "$name")
    mkdir -p "$(dirname "$output")"
    output=$(realpath -m "$output")
    ppm="$output.ppm.tmp"
    rm -f "$ppm"
    printf 'screendump %s\n' "$ppm" | socat - "UNIX-CONNECT:$dir/hmp.sock" >/dev/null
    [[ -s $ppm ]] || {
        echo "QEMU did not produce a framebuffer dump: $ppm" >&2
        exit 1
    }
    ffmpeg -nostdin -y -loglevel error -i "$ppm" "$output"
    rm -f "$ppm"
    file "$output"
}

monitor_vm() {
    local name=$1 command=$2 dir
    dir=$(vm_dir "$name")
    [[ -S "$dir/hmp.sock" ]] || {
        echo "monitor socket unavailable: $dir/hmp.sock" >&2
        exit 1
    }
    printf '%s\n' "$command" | socat - "UNIX-CONNECT:$dir/hmp.sock"
}

stop_vm() {
    local name=$1 dir deadline pid
    dir=$(vm_dir "$name")
    pid_is_live "$name" || {
        echo "VM is not running: $name"
        return 0
    }
    read -r pid <"$dir/qemu.pid"
    if [[ -S "$dir/qga.sock" ]]; then
        "$qga_exec" "$dir/qga.sock" 'systemctl poweroff' --timeout 10 >/dev/null 2>&1 || true
    fi
    deadline=$((SECONDS + 60))
    while kill -0 "$pid" 2>/dev/null && ((SECONDS < deadline)); do sleep 1; done
    if kill -0 "$pid" 2>/dev/null; then
        printf 'quit\n' | socat - "UNIX-CONNECT:$dir/hmp.sock" >/dev/null 2>&1 || true
    fi
    deadline=$((SECONDS + 15))
    while kill -0 "$pid" 2>/dev/null && ((SECONDS < deadline)); do sleep 1; done
    kill -0 "$pid" 2>/dev/null && {
        echo "VM did not stop cleanly: $name (PID $pid)" >&2
        return 1
    }
    echo "VM_STOPPED"
}

case ${1:-} in
    create)
        [[ $# -eq 5 ]] || usage
        create_vm "$2" "$3" "$4" "$5"
        ;;
    clone)
        [[ $# -eq 5 ]] || usage
        clone_vm "$2" "$3" "$4" "$5"
        ;;
    boot-live)
        [[ $# -eq 2 ]] || usage
        boot_vm "$2" live
        ;;
    boot-installed)
        [[ $# -eq 2 ]] || usage
        boot_vm "$2" installed
        ;;
    wait-qga)
        [[ $# -ge 2 && $# -le 3 ]] || usage
        wait_qga "$2" "${3:-360}"
        ;;
    exec)
        [[ $# -ge 3 && $# -le 4 ]] || usage
        name=$2
        dir=$(vm_dir "$name")
        "$qga_exec" "$dir/qga.sock" "$3" --timeout "${4:-300}"
        ;;
    exec-detach)
        [[ $# -eq 3 ]] || usage
        dir=$(vm_dir "$2")
        "$qga_exec" "$dir/qga.sock" "$3" --detach
        ;;
    resume)
        [[ $# -ge 3 && $# -le 4 && $3 =~ ^[0-9]+$ ]] || usage
        dir=$(vm_dir "$2")
        "$qga_exec" "$dir/qga.sock" --pid "$3" --timeout "${4:-30}"
        ;;
    capture)
        [[ $# -eq 3 ]] || usage
        capture_vm "$2" "$3"
        ;;
    monitor)
        [[ $# -eq 3 ]] || usage
        monitor_vm "$2" "$3"
        ;;
    stop)
        [[ $# -eq 2 ]] || usage
        stop_vm "$2"
        ;;
    *) usage ;;
esac
