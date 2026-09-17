if [[ $1 == '' ]] then
    echo building...
    clang -target bpf -Wall -O2 -c ./ebpf/program.c -o ./ebpf/program.o
elif [[ $1 == 'run' ]] then
    echo building and running...
    clang -target bpf -Wall -O2 -c ./ebpf/program.c -o ./ebpf/program.o
    ./ebpf/program
elif [[ $1 == 'clsact' ]] then
    echo creating a clsact qdisk thing...
    sudo tc qdisc add dev lo clsact
else
    echo doing nothing... commands: '', 'run', 'clsact'
fi
