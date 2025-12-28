#!/bin/bash

__version__=0.9.11

# Mensaje redes disponibles
fMensajeRedes() {
    echo "Las redes privadas válidas son:"
    echo "Clase A: 10.X.X.X, Clase B 172.16.X.X a 172.31.X.X y Clase C 192.168.X.X"
    read -p "Introduce una red correcta (Pulse cualquier tecla para continuar)" null
}

# Valida dirección y máscara y calcula broadcast y rangos DHCP
fComprobadorSubnetting() {
    # Lista para comprobar dirección y máscara
    multiplos=(128 64 32 16 8 4 2 1)

    # Diccionario para calcular broadcast
    declare -A dBroadcastOffset

    # Octeto 1
    incrementador=0
    vRestanteOcteto=$vOcteto1
    vRestanteOctetoMask=$vOcteto1mask

    while [[ $incrementador -le 7 ]]; do
        # Comprobar final de bits
        if [[ $vRestanteOcteto -eq 0 ]] || [[ $vRestanteOctetoMask -eq 0 ]]; then
            break
        fi

        # Restar bit a dirección de red
        if [[ $vRestanteOcteto -ge ${multiplos[$incrementador]} ]]; then
            vRestanteOcteto=$(($vRestanteOcteto - ${multiplos[$incrementador]}))
        fi

        # Restar bit a máscara
        if [[ $vRestanteOctetoMask -ge ${multiplos[$incrementador]} ]]; then
            vRestanteOctetoMask=$(($vRestanteOctetoMask - ${multiplos[$incrementador]}))
        fi
        
        incrementador=$(($incrementador + 1))
    done

    if [[ $vRestanteOctetoMask -lt $vRestanteOcteto ]]; then
        read -p "Primer octeto incorrecto (Pulse cualquier tecla para continuar)" input
        return 1
    fi

    # Bucle calculador broadcast Octeto 1
    incrementador=0
    vOctetoBroadcast1=""
    vRestanteOctetoMask=$vOcteto1mask

    dBroadcastOffset["128"]="1"
    dBroadcastOffset["64"]="1"
    dBroadcastOffset["32"]="1"
    dBroadcastOffset["16"]="1"
    dBroadcastOffset["8"]="1"
    dBroadcastOffset["4"]="1"
    dBroadcastOffset["2"]="1"
    dBroadcastOffset["1"]="1"

    while [[ $incrementador -le 7 ]]; do
        # Restar bit a máscara
        if [[ $vRestanteOctetoMask -ge ${multiplos[$incrementador]} ]]; then
            vRestanteOctetoMask=$(($vRestanteOctetoMask - ${multiplos[$incrementador]}))

            # Actualizar diccionario
            dBroadcastOffset["${multiplos[$incrementador]}"]="0"
        fi
        
        incrementador=$(($incrementador + 1))
    done

    ## Actualizar octeto broadcast
    for index in "${!dBroadcastOffset[@]}"; do
        if [[ ${dBroadcastOffset[$index]} -eq 1 ]]; then # Comprobar valor
            vOctetoBroadcast1=$(($vOctetoBroadcast1 + $index))
        fi   
    done
    ## Sumar con el octeto de dirección para unir offset y dirección (Uno de los dos siempre vale 0)
    vOctetoBroadcast1=$(($vOctetoBroadcast1 + $vOcteto1))

    # Octeto 2
    incrementador=0
    vRestanteOcteto=$vOcteto2
    vRestanteOctetoMask=$vOcteto2mask

    while [[ $incrementador -le 7 ]]; do
        if [[ $vRestanteOcteto -eq 0 ]] || [[ $vRestanteOctetoMask -eq 0 ]]; then
            break
        fi

        if [[ $vRestanteOcteto -ge ${multiplos[$incrementador]} ]]; then
            vRestanteOcteto=$(($vRestanteOcteto - ${multiplos[$incrementador]}))
        fi

        if [[ $vRestanteOctetoMask -ge ${multiplos[$incrementador]} ]]; then
            vRestanteOctetoMask=$(($vRestanteOctetoMask - ${multiplos[$incrementador]}))
        fi
        
        incrementador=$(($incrementador + 1))
    done

    if [[ $vRestanteOctetoMask -lt $vRestanteOcteto ]]; then
        read -p "Segundo octeto incorrecto (Pulse cualquier tecla para continuar)" input
        return 1
    fi

    # Bucle calculador broadcast Octeto 2
    incrementador=0
    vOctetoBroadcast2=""
    vRestanteOctetoMask=$vOcteto2mask

    dBroadcastOffset["128"]="1"
    dBroadcastOffset["64"]="1"
    dBroadcastOffset["32"]="1"
    dBroadcastOffset["16"]="1"
    dBroadcastOffset["8"]="1"
    dBroadcastOffset["4"]="1"
    dBroadcastOffset["2"]="1"
    dBroadcastOffset["1"]="1"

    while [[ $incrementador -le 7 ]]; do
        # Restar bit a máscara
        if [[ $vRestanteOctetoMask -ge ${multiplos[$incrementador]} ]]; then
            vRestanteOctetoMask=$(($vRestanteOctetoMask - ${multiplos[$incrementador]}))

            # Actualizar diccionario
            dBroadcastOffset["${multiplos[$incrementador]}"]="0"
        fi
        
        incrementador=$(($incrementador + 1))
    done

    ## Actualizar octeto broadcast
    for index in "${!dBroadcastOffset[@]}"; do
        if [[ ${dBroadcastOffset[$index]} -eq 1 ]]; then
            vOctetoBroadcast2=$(($vOctetoBroadcast2 + $index))
        fi   
    done
    ## Sumar con el octeto de dirección para unir offset y dirección
    vOctetoBroadcast2=$(($vOctetoBroadcast2 + $vOcteto2))

    # Octeto 3
    incrementador=0
    vRestanteOcteto=$vOcteto3
    vRestanteOctetoMask=$vOcteto3mask

    while [[ $incrementador -le 7 ]]; do
        if [[ $vRestanteOcteto -eq 0 ]] || [[ $vRestanteOctetoMask -eq 0 ]]; then
            break
        fi

        if [[ $vRestanteOcteto -ge ${multiplos[$incrementador]} ]]; then
            vRestanteOcteto=$(($vRestanteOcteto - ${multiplos[$incrementador]}))
        fi

        if [[ $vRestanteOctetoMask -ge ${multiplos[$incrementador]} ]]; then
            vRestanteOctetoMask=$(($vRestanteOctetoMask - ${multiplos[$incrementador]}))
        fi
        
        incrementador=$(($incrementador + 1))
    done

    if [[ $vRestanteOctetoMask -lt $vRestanteOcteto ]]; then
        read -p "Tercer octeto incorrecto (Pulse cualquier tecla para continuar)" input
        return 1
    fi

    # Bucle calculador broadcast Octeto 3
    incrementador=0
    vOctetoBroadcast3=""
    vRestanteOctetoMask=$vOcteto3mask

    dBroadcastOffset["128"]="1"
    dBroadcastOffset["64"]="1"
    dBroadcastOffset["32"]="1"
    dBroadcastOffset["16"]="1"
    dBroadcastOffset["8"]="1"
    dBroadcastOffset["4"]="1"
    dBroadcastOffset["2"]="1"
    dBroadcastOffset["1"]="1"

    while [[ $incrementador -le 7 ]]; do
        # Restar bit a máscara
        if [[ $vRestanteOctetoMask -ge ${multiplos[$incrementador]} ]]; then
            vRestanteOctetoMask=$(($vRestanteOctetoMask - ${multiplos[$incrementador]}))

            # Actualizar diccionario
            dBroadcastOffset["${multiplos[$incrementador]}"]="0"
        fi
        
        incrementador=$(($incrementador + 1))
    done

    ## Actualizar octeto broadcast
    for index in "${!dBroadcastOffset[@]}"; do
        if [[ ${dBroadcastOffset[$index]} -eq 1 ]]; then
            vOctetoBroadcast3=$(($vOctetoBroadcast3 + $index))
        fi   
    done
    ## Sumar con el octeto de dirección para unir offset y dirección
    vOctetoBroadcast3=$(($vOctetoBroadcast3 + $vOcteto3))

    # Octeto 4
    incrementador=0
    vRestanteOcteto=$vOcteto4
    vRestanteOctetoMask=$vOcteto4mask

    while [[ $incrementador -le 7 ]]; do
        if [[ $vRestanteOcteto -eq 0 ]] || [[ $vRestanteOctetoMask -eq 0 ]]; then
            break
        fi

        if [[ $vRestanteOcteto -ge ${multiplos[$incrementador]} ]]; then
            vRestanteOcteto=$(($vRestanteOcteto - ${multiplos[$incrementador]}))
        fi

        if [[ $vRestanteOctetoMask -ge ${multiplos[$incrementador]} ]]; then
            vRestanteOctetoMask=$(($vRestanteOctetoMask - ${multiplos[$incrementador]}))
        fi

        incrementador=$(($incrementador + 1))
    done

    if [[ $vRestanteOctetoMask -lt $vRestanteOcteto ]]; then
        read -p "Cuarto octeto incorrecto (Pulse cualquier tecla para continuar)" input
        return 1
    fi
    
    # <-- Dirección y máscara correcta
    # Bucle calculador broadcast Octeto 4
    incrementador=0
    vOctetoBroadcast4=""
    vRestanteOctetoMask=$vOcteto4mask

    dBroadcastOffset["128"]="1"
    dBroadcastOffset["64"]="1"
    dBroadcastOffset["32"]="1"
    dBroadcastOffset["16"]="1"
    dBroadcastOffset["8"]="1"
    dBroadcastOffset["4"]="1"
    dBroadcastOffset["2"]="1"
    dBroadcastOffset["1"]="1"

    while [[ $incrementador -le 7 ]]; do
        # Restar bit a máscara
        if [[ $vRestanteOctetoMask -ge ${multiplos[$incrementador]} ]]; then
            vRestanteOctetoMask=$(($vRestanteOctetoMask - ${multiplos[$incrementador]}))

            # Actualizar diccionario
            dBroadcastOffset["${multiplos[$incrementador]}"]="0"
        fi
        
        incrementador=$(($incrementador + 1))
    done

    ## Actualizar octeto broadcast
    for index in "${!dBroadcastOffset[@]}"; do
        if [[ ${dBroadcastOffset[$index]} -eq 1 ]]; then
            vOctetoBroadcast4=$(($vOctetoBroadcast4 + $index))
        fi   
    done
    ## Sumar con el octeto de dirección para unir offset y dirección
    vOctetoBroadcast4=$(($vOctetoBroadcast4 + $vOcteto4))

    # Resultado
    ## Calcular IP del servidor
    servidorIP="$vOcteto1.$vOcteto2.$vOcteto3.$(($vOcteto4 + 1))"

    ## Calcular broadcast
    broadcast="$vOctetoBroadcast1.$vOctetoBroadcast2.$vOctetoBroadcast3.$vOctetoBroadcast4"
    
    ## Calcular inicio y final rango
    ### Calcular margen disponible (cifras)
    vDiferenciaBroadcastRed=$(($vOctetoBroadcast4 - $vOcteto4))
    aDigitosOcteto4=()

    ### Separar cifras Octeto 4
    for ((i=0; i<${#vOcteto4}; i++)); do
        aDigitosOcteto4[i]="${vOcteto4:$i:1}"
    done

    ### Separar cifras Octeto broadcast 4
    for ((i=0; i<${#vOctetoBroadcast4}; i++)); do
        aDigitosOctetoBroadcast4[i]="${vOctetoBroadcast4:$i:1}"
    done

    ### Comprobar número de dígitos del cuarto octeto de la dirección de red y margen
    if [[ $vDiferenciaBroadcastRed -ge 31 && ${#vOcteto4} -eq 3 ]]; then # Comprobar cifras margen y octeto
        aDigitosOcteto4[1]=$((${aDigitosOcteto4[1]} + 1))
        aDigitosOcteto4[2]=1

        # Recrear octeto
        vOcteto4RangoMin="${aDigitosOcteto4[0]}${aDigitosOcteto4[1]}${aDigitosOcteto4[2]}"
    fi
    if [[ $vDiferenciaBroadcastRed -ge 31 ]] && [[ ${#vOcteto4} -eq 2 || ${#vOcteto4} -eq 1 ]]; then # Comprobar cifras margen y octeto
        aDigitosOcteto4[0]=$((${aDigitosOcteto4[0]} + 1))
        aDigitosOcteto4[1]=1

        # Recrear octeto
        vOcteto4RangoMin="${aDigitosOcteto4[0]}${aDigitosOcteto4[1]}"
    fi

    ### Comprobar número de dígitos del cuarto octeto del broadcast
    if [[ ${#vOctetoBroadcast4} -eq 3 ]]; then # Comprobar cifras octeto broadcast
        aDigitosOctetoBroadcast4[2]=0

        # Recrear octeto
        vOcteto4RangoMax="${aDigitosOctetoBroadcast4[0]}${aDigitosOctetoBroadcast4[1]}${aDigitosOctetoBroadcast4[2]}"
    fi
    if [[ ${#vOctetoBroadcast4} -eq 2 ]]; then # Comprobar cifras octeto broadcast
        aDigitosOctetoBroadcast4[1]=0

        # Recrear octeto
        vOcteto4RangoMax="${aDigitosOctetoBroadcast4[0]}${aDigitosOctetoBroadcast4[1]}"
    fi

    ### Para redes CIDR /30-28
    if [[ $vDiferenciaBroadcastRed -lt 31 ]]; then
        vOcteto4RangoMin=$(($vOcteto4 + 1))
        vOcteto4RangoMax=$(($vOctetoBroadcast4 - 1))
    fi
    vRangoDHCPmin=$vOcteto1.$vOcteto2.$vOcteto3.$vOcteto4RangoMin
    vRangoDHCPmax=$vOctetoBroadcast1.$vOctetoBroadcast2.$vOctetoBroadcast3.$vOcteto4RangoMax
    
    echo "IP servidor:" $servidorIP
    echo "Broadcast:" $broadcast
    echo "Rango DHCP:" $vRangoDHCPmin - $vRangoDHCPmax
    read -p "Pausa (Pulse cualquier tecla para continuar)" input

    # Salida con éxito
    return 0
}

# Calculador de máscaras completas
fCider() {
    sufijo=$1

    case $sufijo in
        30) vMascaraCompleta="255.255.255.252";;
        29) vMascaraCompleta="255.255.255.248";;
        28) vMascaraCompleta="255.255.255.240";;
        27) vMascaraCompleta="255.255.255.224";;
        26) vMascaraCompleta="255.255.255.192";;
        25) vMascaraCompleta="255.255.255.128";;
        24) vMascaraCompleta="255.255.255.0";;
        23) vMascaraCompleta="255.255.254.0";;
        22) vMascaraCompleta="255.255.252.0";;
        21) vMascaraCompleta="255.255.248.0";;
        20) vMascaraCompleta="255.255.240.0";;
        19) vMascaraCompleta="255.255.224.0";;
        18) vMascaraCompleta="255.255.192.0";;
        17) vMascaraCompleta="255.255.128.0";;
        16) vMascaraCompleta="255.255.0.0";;
        15) vMascaraCompleta="255.254.0.0";;
        14) vMascaraCompleta="255.252.0.0";;
        13) vMascaraCompleta="255.248.0.0";;
        12) vMascaraCompleta="255.240.0.0";;
        11) vMascaraCompleta="255.224.0.0";;
        10) vMascaraCompleta="255.192.0.0";;
        9) vMascaraCompleta="255.128.0.0";;
        8) vMascaraCompleta="255.0.0.0";;
    esac

    IFS='.' read -r vOcteto1mask vOcteto2mask vOcteto3mask vOcteto4mask <<< "$vMascaraCompleta"

}

# Menú
servidor=""
red=""
dominio=""

while true; do

    clear

    echo "----------------------------------------------"
    echo "    Proyecto SRI 2º ASIR v$__version__ - Kevin M."
    echo "----------------------------------------------"
    echo "(1) Nombre servidor ("$servidor")"
    echo "(2) Dirección de red ("$red")"
    echo "(3) Dominio ("$dominio")"
    echo "(4) Empezar"
    echo "(0) Salir"
    echo "----------------------------------------------"
    read -p "Introduce una opción; " input

    case $input in
        1)
            while true; do
                clear
                read -p "Introduce nombre del servidor: " servidor
                if [ "$servidor" ]; then
                    break
                else
                    read -p "Introduce un nombre correcto (Pulse cualquier tecla para continuar)" null
                fi
            done ;;

        2)
            while true; do
                # Resetear variables
                vOcteto1=""
                vOcteto2=""
                vOcteto3=""
                vOcteto4=""

                vDireccion="" # Dir. Red
                vMascara=""
                red="" # Dir. Red & CIDR
                bRFC1918=""
                input="" # Variable comprobación inputs

                clear

                # Habilitar o deshabilitar estándar RFC 1918 de redes privadas
                read -p "¿Quieres realizar comprobación de redes RFC 1918? (S/n): " input
                if ! [[ $input ]] || [[ $input == "S" || $input == "s" ]]; then
                    bRFC1918=1
                fi

                read -p "Introduce dirección y máscara de red (10.X.X.X/8 - 192.168.X.X/30): " red
                IFS='/' read -r vDireccion vMascara <<< "$red" # Internal field separator (variable especial)
                IFS='.' read -r vOcteto1 vOcteto2 vOcteto3 vOcteto4 <<< "$vDireccion"

                # Comprobar todos los octetos introducidos (En caso contrario la comprobación de -ge con "" equivale a 0 y falla)
                if ! [[ $vOcteto1 && $vOcteto2 && $vOcteto3 && $vOcteto4 ]]; then
                    read -p "Introduce una dirección correcta  (Pulse cualquier tecla para continuar)" null
                    continue
                fi

                # Comprobar máscara
                if [[ "$vMascara" -ge 8 && "$vMascara" -le 30 ]]; then
                    fCider $vMascara
                else
                    read -p "Introduce una máscara correcta  (Pulse cualquier tecla para continuar)" null
                    continue
                fi

                if [[ $bRFC1918 ]]; then
                    # Comprobar octetos en caso de habilitar RFC 1918
                    if [[ "$vOcteto1" -eq 10 && "$vOcteto2" -ge 0 && "$vOcteto2" -le 255 && "$vOcteto3" -ge 0 && "$vOcteto3" -le 255 && "$vOcteto4" -ge 0 && "$vOcteto4" -le 255 ]]; then
                        # Clase A
                        # Comprobar dirección y máscara
                        if fComprobadorSubnetting; then
                            break
                        fi
                    fi

                    if [[ "$vOcteto1" -eq 172 && "$vOcteto2" -ge 16 && "$vOcteto2" -le 31 && "$vOcteto3" -ge 0 && "$vOcteto3" -le 255 && "$vOcteto4" -ge 0 && "$vOcteto4" -le 255 ]]; then
                        # Clase B
                        # Comprobar dirección y máscara
                        if fComprobadorSubnetting; then
                            break
                        fi
                    fi

                    if [[ "$vOcteto1" -eq 192 && "$vOcteto2" -eq 168 && "$vOcteto3" -ge 0 && "$vOcteto3" -le 255 && "$vOcteto4" -ge 0 && "$vOcteto4" -le 255 ]]; then
                        # Clase C
                        # Comprobar dirección y máscara
                        if fComprobadorSubnetting; then
                            break
                        fi
                    fi

                    fMensajeRedes   # Informar rangos disponibles
                else
                    if fComprobadorSubnetting; then
                        break
                    fi
                fi
            done ;;
        
        3)
            while true; do
                clear
                read -p "Introduce nombre del dominio: " dominio
                if [ "$dominio" ]; then
                    break
                else
                    read -p "Introduce un nombre correcto (Pulse cualquier tecla para continuar)" null
                fi
            done ;;

        4)
            # Configuración de red
            if [[ $red && $servidorIP ]]; then
                echo "Configurando configuración de red..."
                echo "$vOcteto1.$vOcteto2.$vOcteto3.$(($vOcteto4+1))/$mascara"

                sudo nmcli connection modify enp0s8 \
                    ipv4.method manual \
                    ipv4.addresses "$vOcteto1.$vOcteto2.$vOcteto3.$(($vOcteto4+1))/$vMascara" \
                    ipv4.dns "$servidorIP"

                sudo nmcli connection down enp0s8
                sudo nmcli connection up enp0s8
            fi
            # -------------------------------------------------------------

            # Configuración /etc/hostname
            if [[ $servidor ]]; then
                echo "Configurando archivo hostname..."

                cat > /etc/hostname <<- EOF
$servidor
EOF
            fi
            # -------------------------------------------------------------

            # Configuración /etc/hosts
            if [[ $servidor && $servidorIP && $dominio ]]; then
                echo "Configurando archivo hosts..."

                cat >> /etc/hosts <<- EOF
127.0.0.1       localhost
127.0.1.1       $servidor.$dominio $servidor
$servidorIP     $servidor.$dominio $servidor
EOF
            fi
            # -------------------------------------------------------------

            # Configuración DHCP Server
            if [[ $dominio && $servidorIP && $vDireccion && $vMascaraCompleta && $vRangoDHCPmin && $vRangoDHCPmax && $broadcast ]]; then
                echo "Instalando servicio isc-dhcp-server..."
                apt install isc-dhcp-server

                echo "Configurando archivo /etc/default/isc-dhcp-server..."
                cat > /etc/default/isc-dhcp-server <<- EOF
INTERFACESv4="enp0s8"
INTERFACESv6=""
EOF

                echo "Configurando archivo /etc/dhcp/dhcpd.conf..."
                cat > /etc/dhcp/dhcpd.conf <<- EOF
option domain-name "$dominio";
option domain-name-servers $servidorIP;

default-lease-time 600;
max-lease-time 7200;

subnet $vDireccion netmask $vMascaraCompleta {
  range $vRangoDHCPmin $vRangoDHCPmax;
  option domain-name-servers $servidorIP;
  option domain-name "$dominio";
  option subnet-mask $vMascaraCompleta;
  option routers $servidorIP;
  option broadcast-address $broadcast;
  default-lease-time 600;
  max-lease-time 7200;
}
EOF
                # Habilitar y reiniciar servicio
                echo "Habilitando servicio y reinicio del daemon"
                systemctl enable isc-dhcp-server
            fi
            # -------------------------------------------------------------

            # Configuración servicio SSH
            echo "Instalando servicio openssh-server..."
            apt install openssh-server

            ## Crear archivo bienvenida 
            echo "Creando archivo mensaje"
            cat > /etc/mensaje.net <<- EOF
╔═══════════════════════════════════════╗
║       SERVIDOR SRI - $dominio         ║
║       Curso 2025/2026 - 2º ASIR       ║
╚═══════════════════════════════════════╝
EOF

            echo "Configurando archivo /etc/ssh/sshd_config..."
            cat >> /etc/ssh/sshd_config <<- EOF
PermitRootLogin yes
Banner /etc/mensaje.net
EOF
            echo "Habilitando y reiniciando daemon openssh-server..."
            systemctl enable openssh-server
            # -------------------------------------------------------------

            # Configuración NAT (Iptables)
            echo "Instalando iptables-persistent..."
            apt install iptables-persistent

            echo "Configurando /etc/sysctl.conf..."
            cat > /etc/sysctl.conf <<- EOF
net.ipv4.ip_forward=1
EOF
            echo "Configurando reglas Iptables..."
            iptables -F
            iptables -t nat -F
            iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE
            iptables -A FORWARD -i enp0s8 -o enp0s3 -j ACCEPT
            iptables -A FORWARD -i enp0s3 -o enp0s8 -m state --state RELATED,ESTABLISHED -j ACCEPT

            echo "Guardando reglas..."
            netfilter-persistent save
            netfilter-persistent reload
            # -------------------------------------------------------------

            # Configuración DNS (Bind9)
            if [[ $dominio && $red && $vOcteto1 && $vOcteto2 && $vOcteto3 && $vOcteto4 && $servidor && $servidorIP ]]; then
                echo "Instalando servicio..."
                apt install bind9

                ## Configurando /etc/resolv.conf
                echo "Configurando /etc/resolv.conf"
                cat > /etc/resolv.conf <<- EOF
nameserver 127.0.0.1
nameserver 8.8.8.8
search $dominio
EOF
                ## Configurando /etc/bind/named.conf.options
                echo "Configurando /etc/bind/named.conf.options..."
                cat > /etc/bind/named.conf.options <<- EOF
options {
    directory "/var/cache/bind";
    listen-on { any; }; # Escucha en todas interfaces
    
    recursion yes; # Resuelve cualquier zona
    allow-recursion { $red; 127.0.0.1; }; # Scope de recursion
    
    forwarders {
        8.8.8.8;
        1.1.1.1;
    };
    
    forward only; # Siempre usa forwarder para consultas fuera del dominio
    
    dnssec-validation auto; # Criptografia
};
EOF
                ## Configurando /etc/bind/named.conf.local
                echo "Configurando /etc/bind/named.conf.local..."
                cat > /etc/bind/named.conf.local <<- EOF
zone "$dominio" {
    type master;
    file "/var/lib/bind/$dominio.hosts";
};

zone "$vOcteto3.$vOcteto2.$vOcteto1.in-addr.arpa" { 
        type master;
        file "/var/lib/bind/$vOcteto1.$vOcteto2.$vOcteto3-inversa.rev";
};

zone "marca.com" {
    type master;
    file "/var/lib/bind/bloqueados.zone";
    allow-query { any; };
};
EOF
                ## Configurando /var/lib/bind/dominio.hosts
                echo "Configurando /var/lib/bind/$dominio.hosts..."
                cat > /var/lib/bind/$dominio.hosts <<- EOF
\$TTL 7200

$dominio.       IN      SOA             $dominio.       admin.$dominio. (
                                                20251213
                                                1000
                                                1000
                                                1000
                                                1000 )

$dominio.       IN      NS              $servidor.$dominio.

$dominio.       IN      A       $servidorIP
$servidor            IN      A       $servidorIP     
www             IN      A       $servidorIP
ftp             IN      A       $servidorIP
EOF

                ## Configurando /var/lib/bind/vOcteto1.vOcteto2.vOcteto3-inversa.rev
                echo "Configurando /var/lib/bind/$vOcteto1.$vOcteto2.$vOcteto3-inversa.rev..."
                cat > /var/lib/bind/$vOcteto1.$vOcteto2.$vOcteto3-inversa.rev <<- EOF
\$TTL 7200

$vOcteto3.$vOcteto2.$vOcteto1.in-addr.arpa.    IN    SOA        $servidor.$dominio.    admin.$dominio. (
                                    20251212
                                    1000
                                    1000
                                    1000
                                    1000 )

$vOcteto3.$vOcteto2.$vOcteto1.in-addr.arpa.        IN    NS    $servidor.$dominio.
$(($vOcteto4 + 1)).$vOcteto3.$vOcteto2.$vOcteto1.in-addr.arpa.    IN    PTR    $servidor.$dominio.
EOF

                ## Configurando /var/lib/bind/bloqueados.zone
                echo "Configurando /var/lib/bind/bloqueados.zone..."
                cat > /var/lib/bind/bloqueados.zone <<- EOF
\$TTL  7200
@    IN    SOA localhost. admin.localhost. (
        20251212
        1000
        1000
        1000
        1000 )

@       IN    NS    localhost.
@       IN    A     127.0.0.1
www     IN    A     127.0.0.1
EOF

                ## Habilitar y reiniciar daemon bind9
                echo "Habilitando y reiniciando daemon bind9"
                systemctl enable bind9
            fi
            # -------------------------------------------------------------

            # Configuración Apache
            if [[ $dominio ]]; then
                ## Instalar Apache
                echo "Instalando servicio apache2..."
                apt install apache2

                ## Ruta web
                echo "Creando /var/www/html/$dominio..."
                mkdir /var/www/html/$dominio

                ## Configuración index html
                echo "/var/www/html/$dominio/index.html..."
                cat > /var/www/html/$dominio/index.html <<- EOF
<!DOCTYPE html>
<html>
<head><title>Inicio</title></head>
<body><h1>Inicio</h1></body>
</html>
EOF

                ## Configuración sitio apache
                echo "Configurando /etc/apache2/sites-available/$dominio.conf..."
                cat > /etc/apache2/sites-available/$dominio.conf <<- EOF
<VirtualHost *:80>
    ServerName www.$dominio
    DocumentRoot /var/www/html/$dominio

    # ruta descargas protegida
    Alias /descargas /var/www/html/$dominio/descargas
    <Directory "/var/www/html/$dominio/descargas">
        AuthType Basic
        AuthName "Descargas Restringidas"
        AuthUserFile /etc/apache2/.htpasswd_descargas
        Require user descargas
    </Directory>

    # ruta ftp
    Alias /ftp /var/www/html/proyecto/ftp
    <Directory "/var/www/html/proyecto/ftp">
        AuthType Basic
        AuthName "Acceso FTP Proyecto"
        AuthUserFile /etc/apache2/.htpasswd_ftp
        Require user ftpproyecto
        IndexOptions FancyIndexing NameWidth=* HTMLTable
    </Directory>
</VirtualHost>
EOF
                ## Creación directorios descargas y ftp
                echo "Creando directorios /var/www/html/$dominio/descargas y /var/www/html/proyecto/ftp..."
                mkdir -p /var/www/html/$dominio/descargas
                mkdir -p /var/www/html/proyecto/ftp

                ## Configuración index descargas y ftp
                echo "Configurando /var/www/html/$dominio/descargas/index.html..."
                cat > /var/www/html/$dominio/descargas/index.html <<- EOF
<!DOCTYPE html>
<html>
<head><title>Descargas</title></head>
<body><h1>Descargas</h1></body>
</html>
EOF
                echo "Configurando /var/www/html/$dominio/ftp/hola.txt..."
                cat > /var/www/html/$dominio/ftp/hola.txt <<- EOF
Hola
EOF
                ## Creación archivos contraseñas
                echo "Creando archivo /etc/apache2/.htpasswd_descargas..."
                htpasswd -cb /etc/apache2/.htpasswd_descargas descargas 'descargas'

                echo "Creando archivo /etc/apache2/.htpasswd_ftp..."
                htpasswd -cb /etc/apache2/.htpasswd_ftp ftpproyecto 'ftpproyecto'

                ## Habilitar sitio
                echo "Habilitando $dominio.conf..."
                a2ensite $dominio.conf

                ## Habilitar plugin autenticación y alias
                echo "Habilitando plugin autenticación y alias..."
                a2enmod auth_basic authn_file alias

                ## Recargar apache
                echo "Recargando daemon apache2..."
                systemctl enable apache2
            fi

            # Configuración servicio FTP
            if [[ $servidorIP ]]; then
                ## Instalación servicio vsftpd
                echo "Instalando vsftpd..."
                apt install vsftpd

                ## Configuración /etc/vsftpd.conf
                echo "Configurando /etc/vsftpd.conf"
                cat > /etc/vsftpd.conf <<- EOF
# Configuración básica
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES

# Seguridad y chroot
chroot_local_user=YES
chroot_list_enable=YES
chroot_list_file=/etc/vsftpd.chroot_list
allow_writeable_chroot=YES

# Límites y timeout
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO

# Puerto pasivo (importante para clientes detrás de firewalls)
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100
pasv_address=$servidorIP  # IP Servidor
EOF
                ## Creación usuario ftpproyecto
                echo "Creando y configurando usuario ftpproyecto..."

                adduser ftpproyecto
                usermod -d /var/www/html/proyecto/ftp ftpproyecto
                chown -R ftpproyecto:ftpproyecto /var/www/html/proyecto/ftp
                chmod 755 /var/www/html/proyecto/ftp
                echo "ftpproyecto" | tee /etc/vsftpd.chroot_list

                ## Habilitar y reiniciar servicio vsftpd
                echo "Habilitando y reiniciando daemon vsftpd..."
                systemctl enable vsftpd
            fi

            # Configuración Zabbix
            echo "Descargando Zabbix 6.0-4..."
            wget https://repo.zabbix.com/zabbix/6.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_6.0-4+ubuntu22.04_all.deb
            
            echo "Instalando repositorio Zabbix..."
            dpkg -i zabbix-release_6.0-4+ubuntu22.04_all.deb && apt update
            
            echo "Instalando requisitos..."
            apt install zabbix-server-mysql zabbix-agent zabbix-apache-conf zabbix-sql-scripts zabbix-frontend-php libapache2-mod-php -y
        
            echo "Configurando base de datos..."
            mysql -uroot -e "drop database zabbix;"
            mysql -uroot -e "create database zabbix character set utf8mb4 collate utf8mb4_bin;"
            mysql -uroot -e "create user 'zabbix@localhost' identified by 'zabbix';"
            mysql -uroot -e "grant all privileges on zabbix.* to 'zabbix@localhost';"
            mysql -uroot -e "set global log_bin_trust_function_creators = 1;"

            echo "Importando estructura base de datos..."
            zcat /usr/share/zabbix-sql-scripts/mysql/server.sql.gz | mysql --default-character-set=utf8mb4 -uzabbix -pzabbix zabbix
            
            echo "Deshabilitando log_bin_trust_function_creators..."
            mysql -uroot -e "set global log_bin_trust_function_creators = 0;"

            echo "Configurando archivo servicio /etc/zabbix/zabbix_server.conf"
            cat >> /etc/zabbix/zabbix_server.conf <<- EOF
DBPassword=zabbix
EOF

            echo "Configurando archivo php /etc/php/8.1/fpm/php.ini"
            cat >> /etc/php/8.1/fpm/php.ini <<- EOF
max_input_time = 300
post_max_size = 16M
EOF
            echo "Habilitando daemon Zabbix..."
            sudo systemctl enable zabbix-server zabbix-agent
            # ---------------------------------------------------------

            # Configurar Rsync
            echo "Instalando Rsync..."
            apt install rsync

            echo "Creando directorio Copias de seguridad..."
            mkdir /mnt/Backups-rsync
            mount /dev/sdb /mnt/Backups-rsync/ # Montar unidad

            mkdir /mnt/Backups-rsync/ser1
            mkdir /mnt/Backups-rsync/dhcp
            mkdir /mnt/Backups-rsync/ssh
            mkdir /mnt/Backups-rsync/iptables
            mkdir /mnt/Backups-rsync/bind9
            mkdir /mnt/Backups-rsync/apache
            mkdir /mnt/Backups-rsync/vsftpd
            mkdir /mnt/Backups-rsync/zabbix

            echo "Creando archivo ejecutable backup-rsync.sh..."
            cat > ./backup-rsync.sh <<- EOF
#!/bin/bash

# Configuración
ser1="/mnt/Backups-rsync/ser1"
dhcp="/mnt/Backups-rsync/dhcp"
ssh="/mnt/Backups-rsync/ssh"
iptables="/mnt/Backups-rsync/iptables"
bind9="/mnt/Backups-rsync/bind9"
apache="/mnt/Backups-rsync/apache"
vsftpd="/mnt/Backups-rsync/vsftpd"
zabbix="/mnt/Backups-rsync/zabbix"

# Ser1
echo Realizando copia archivos del servidor
rsync -az /etc/hosts \$ser1
echo OK

# DHCP
echo Realizando copia archivos del DHCP
rsync -az /etc/default/isc-dhcp-server \$dhcp
rsync -az /etc/dhcp/dhcpd.conf \$dhcp
echo OK

# SSH
echo Realizando copia archivos del SSH
rsync -az /etc/ssh/sshd_config \$ssh
echo OK

# Iptables
echo Realizando copia archivos de Iptables
rsync -az /etc/sysctl.conf \$iptables
iptables-save > \$iptables
echo OK

# DNS
echo Realizando copia archivos de Bind9
rsync -az --relative /etc/resolv.conf \$bind9
rsync -az --relative /etc/bind \$bind9
rsync -az --relative /var/lib/bind \$bind9
echo OK

# Apache
echo Realizando copia archivos de Apache
rsync -az /var/www/html/pro05.es \$apache
rsync -az /etc/apache2 \$apache
echo OK

# FTP
echo Realizando copia archivos de Vsftpd
rsync -az /etc/vsftpd.conf \$ftp
echo OK

# Zabbix
echo Realizando copia archivos de Zabbix
rsync -az /etc/zabbix \$zabbix
rsync -az /etc/mysql \$zabbix
echo OK
EOF

            echo "Permitir ejecución"
            chmod +x ./backup-rsync.sh

            echo "Actualizando crontab..."
            sh -c '(crontab -u usuario -l 2>/dev/null; echo "0 2 * * * /home/usuario/backup-rsync.sh") | crontab -u usuario -'

            # Final, reiniciando todos los servicios
            systemctl restart isc-dhcp-server sshd bind9 apache2 vsftpd zabbix-server zabbix-agent 2>/dev/null
            read -p "Terminado (Pulse cualquier tecla para continuar)" null
            ;;

        0) break ;;
        *) read -p "Introduce una opción correcta (Pulse cualquier tecla para continuar)" null ;;
    esac
done
