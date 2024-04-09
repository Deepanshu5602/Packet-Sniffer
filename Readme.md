
## Execution in Linux

To execute the following code in Linux, follow these steps:

1. Update the package lists:

```bash
sudo apt-get update
```

2. Install the build essentials:

```bash
sudo apt-get install build-essential
```

3. Install libpcap:

```bash
sudo apt-get install libpcap-dev
```

## Compilation and Running

To compile and run the code, use the following commands:

1. Compile the `packet.c` file with the `libpcap` library:

```bash
gcc packet.c -lpcap -o packet
```

2. Run the executable with the specified parameters:

```bash
sudo ./packet [Protocol] [Number of Packets{0 if infinite}]
```

3. Select the network interface:

- To use any available interface, enter `any`.
- To use any perticular interface, write its name from the list.

4. Enter the search keyword:

- For passwords and usernames, enter the keyword for these used on the accessed website.(you must know it beforhand to access them)
