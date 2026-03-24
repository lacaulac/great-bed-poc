alias rc := run-chisel
alias rc-into := run-chisel-into-file
alias rc-col := run-chisel-piped
alias rc-colsel := run-chisel-piped-sel
alias col-file := run-collector-from-file

userfilter := "user.uid=1001"
filter  := "not(fd.name contains 'mozilla') and not(fd.name contains '/dev/pts') and not(fd.name contains '/.config/Neo4j Desktop/Application/relate-data/dbmss/')"
sysdigcmd := "sysdig --modern-bpf"
fifopath := `mktemp --dry-run --suffix .fifo`
uv := `which uv`

run-chisel:
    sudo {{sysdigcmd}} -c cbor_events "{{userfilter}} and {{filter}}"

run-chisel-into-file:
    sudo {{sysdigcmd}} -c cbor_events  > /tmp/data.cbor

run-chisel-piped:
    mkfifo {{fifopath}}
    sudo {{sysdigcmd}} -c cbor_events "{{filter}}" > {{fifopath}} &
    sudo {{uv}} run --directory collectors/cbor_events/ main.py {{fifopath}}
    rm -f {{fifopath}}
    sudo killall sysdig

run-chisel-piped-sel:
    mkfifo {{fifopath}}
    sudo {{sysdigcmd}} -c cbor_events "{{userfilter}} and {{filter}}" > {{fifopath}} &
    sudo {{uv}} run --directory collectors/cbor_events/ main.py {{fifopath}}
    rm -f {{fifopath}}
    sudo killall sysdig

run-collector-from-file:
    cat /tmp/data.cbor | uv run collectors/cbor_events/main.py
