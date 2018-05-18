#!/usr/bin/env bash

# MAC 18/05/18
# setup script for ETD to setup as a systemd service

PROG_NAME=$(basename $0)
SVC_NAME="etd.service"
BIN_PATH="/usr/bin"
ETC_PATH="/etc/etd"
SYSD_PATH="/lib/systemd/system"

function usage {
    echo "[!] usage: $PROG_NAME [install/uninstall]" 1>&2
    exit 1
}

function check_pip {
    # pip requirements
    if [[ ! -x /usr/bin/pip ]]; then
        echo "[!] pip must be installed first: apt-get install python-pip" 1>&2
        exit 1
    fi
}

function do_install {
    check_pip

    echo "[+] installing pip requirements for root user"
    sudo -H pip install -r requirements.txt

    echo "[+] copying etd.py into /usr/bin"
    cp etd.py $BIN_PATH

    if [[ ! -d $ETC_PATH ]]; then
        echo "[*] $ETC_PATH not found, creating directory"
        mkdir -p $ETC_PATH
    fi

    echo "[+] copying initial etd.yaml config into $ETC_PATH"
    cp etd.yaml $ETC_PATH

    echo "[+] copying $SVC_NAME into $SYSD_PATH"
    cp $SVC_NAME $SYSD_PATH

    echo "[+] systemd daemon reload"
    systemctl daemon-reload

    read -p "[*] enable service (y): " enable

    case $enable in
        y|Y)
            systemctl enable $SVC_NAME
            read -p "[*] start service (y): " start
            case $start in
                y|Y) systemctl start $SVC_NAME;;
            esac
            ;;
    esac
}

function do_uninstall {
    check_pip

    echo "[-] removing pip requirements for root user"
    sudo -H pip uninstall -r requirements.txt

    if [[ -e "$BIN_PATH/etd.py" ]]; then
        echo "[-] removing etd.py from $BIN_PATH"
        rm "$BIN_PATH/etd.py";
    fi

    if [[ -d $ETC_PATH ]]; then
        echo "[-] removing $ETC_PATH"
        rm -fr $ETC_PATH;
    fi

    if [[ -e "$SYSD_PATH/$SVC_NAME" ]]; then
        echo "[-] stopping service"
        systemctl stop $SVC_NAME

        echo "[-] disabling service"
        systemctl disable $SVC_NAME

        echo "[-] removing etd.service from $SYSD_PATH"
        rm "$SYSD_PATH/$SVC_NAME"

        echo "[*] systemd daemon reload"
        systemctl daemon-reload

        echo "[*] systemd reset failed"
        systemctl reset-failed
    fi
}

# grab action from user
action=$1

# check they passed the right action in
if [[ ! "$action" =~ (un)?install ]]; then
    usage
fi

# validate context
if [[ ! -e /usr/lib/systemd ]]; then
    echo "[!] not running with systemd" 1>&2
    exit 1
fi

# run as root
if [[ $EUID -ne 0 ]]; then
    echo "[!] run as root" 1>&2
    exit 1
fi

# do action selected
if [[ "$action" == "install" ]]; then do_install; fi
if [[ "$action" == "uninstall" ]]; then do_uninstall; fi

echo "[*] $action completed"