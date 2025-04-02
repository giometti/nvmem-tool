NVMEM (Non Volatile Memory) tool
================================

This package contains a tool for Linux in order to be able to detect and easily manage NVMEM devices.

Introduction
------------

Linux NVMEM is a Non-Volatile-MEMory layer, which is used to retrieve configuration of SOC or Device specific data from non volatile memories like eeprom, efuses and so on.

This framework introduces DT representation for consumer devices to go get the data they require (MAC Addresses, SoC/Revision ID, part numbers, and so on) from the NVMEMs. For example an ethernet may declare that its
MAC address is located into `ethernet_mac1_address` cell.

    &ethernet1 {
        status = "okay";
        ...
        nvmem-cells = <&ethernet_mac1_address>;
        nvmem-cell-names = "mac-address";
        ...
    };

Where such cell is defined within a FUSEs array as defined below:

    bsec: efuse@5c005000 {
        #address-cells = <1>;
        #size-cells = <1>;

        part_number_otp: part-number-otp@4 {
            ...
            ethernet_mac1_address: mac1@e4 {
                reg = <0xe4 0x6>;
            };
            ethernet_mac2_address: mac2@ea {
                reg = <0xea 0x6>;
            };
        };

Even an EEPROM can be partitioned as shown below:

    &i2c1 {
        eeprom@51 {
            compatible = "atmel,24c64";
            reg = <0x51>;
            pagesize = <32>;

            nvmem-layout {
                compatible = "fixed-layout";
                #address-cells = <1>;
                #size-cells = <1>;
    
                sw_code: sw_code@0 {
                    reg = <0x0 0x20>;
                };
    
                bootpart: bootpart@20 {
                    reg = <0x20 0x20>;
                };
    
                halfhours: halfhours@40 {
                    reg = <0x40 0x20>;
                };
    
                hw_info: hw_info@1000 {
                    reg = <0x1000 0x1000>;
                };
            };
        };
    };

In the above scenario we have four cells mapped as:

| name         | offset | lenght |
|--------------|--------|--------|
| sw_code@0    | 0x00   | 0x20   |
| bootpart@20  | 0x20   | 0x20   |
| halfhours@40 | 0x40   | 0x20   |
| hw_info@1000 | 0x1000 | 0x1000 |

By using the `nvmem-tool` we can detect these cells by using the command line below:

    # nvmem-tool 
    reboot_mode:reboot-mode
    nvram@5c00a100:tamp-bkp@0
    nvram@5c00a100:tamp-bkp@7c
    eeprom@51:bootpart@20
    eeprom@51:hw_info@1000
    eeprom@51:sw_code@0
    eeprom@51:halfhours@40
    adc2:vrefint
    ethernet2:mac-address
    efuse@5c005000:calib@5e
    efuse@5c005000:calib@5c
    ethernet1:mac-address
    efuse@5c005000:part-number-otp@4

Then we can read the cell content with the following command line:

    # nvmem-tool eeprom@51:halfhours@40
    ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
     ff ff ff ff ff 

Then we can write a string within the cell:

    # nvmem-tool --format=string eeprom@51:halfhours@40 1024

And we can read back the just written string:

    # nvmem-tool --format=string eeprom@51:halfhours@40
    1024

We can also print the cell's content as a bytes stream:

    # nvmem-tool eeprom@51:halfhours@40 
    31 30 32 34 00 ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
     ff ff ff ff ff 

And as bytes stream we can write within it:

    # nvmem-tool eeprom@51:halfhours@40 "0xff 0xff 0xff 0xff 0xff"
    # nvmem-tool eeprom@51:halfhours@40
    ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
     ff ff ff ff ff 

Other supported formats are:

* `u8`: for unsigned 8 bits int (default)
* `u16`: for unsigned integer at 16 bits
* `u32`: for unsigned integer at 32 bits
* `u64`: for unsigned integer at 64 bits
* `mac`: for MAC address
* `string`: for ASCII string
* `raw`: for raw data

Latest format, that is `raw`, can be used to read from and write to files. For example,
we can read cell data and write directly into a file:

    # nvmem-tool --format=raw eeprom@51:halfhours@40 > file
    # hexdump -C file
    00000000  31 30 32 34 00 ff ff ff  ff ff ff ff ff ff ff ff  |1024............|
    00000010  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
    00000020

And we can write cell data from file as shown below:

    # tr 4 5 < file > new_file
    # nvmem-tool --format=raw eeprom@51:halfhours@40 - < new_file
    # nvmem-tool --format=string eeprom@51:halfhours@40
    1025

The usage message
-----------------

The current usage message is reported below:

    # nvmem-tool -h
    usage:
            nvmem-tool <options>                                    : list detected NVMEM cells
            nvmem-tool <options> --nvmem                            : list detected NVMEM devices
            nvmem-tool <options> --nvmem=<dev>                      : list cells within the NVMEM device <dev>
            nvmem-tool <options> <cell>                             : read data in the first cell named <cell>
            nvmem-tool <options> --nvmem=<dev> <cell>               , or
            nvmem-tool <options> <dev>:<cell>                       : read data in the cell named <cell> within the NVMEM device <dev>
            nvmem-tool <options> --nvmem=<dev> <cell> <data>        , or
            nvmem-tool <options> <dev>:<cell> <data>                : write <data> in the cell named <cell> within the NVMEM device <dev>
      <options> can be one or more of:
        -h                    : print this helping message
        -d                    : enable debugging messages
        --base10              : print numbers in dec instead of hex
        --porcelain           : enable the porcelain output
        --dump                : enable dump mode
        --show-all            : show also "Unknown" devices
        --format=<fmt>        : show data as "u8", "u16", "u32", "u64", "mac", "string", or "raw"
        --sysfs-dir           : set sysfs mount directory to <dir> (defaults to /sys)
