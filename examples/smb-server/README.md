# SMB Server Example

This example demonstrates how to create a complete SMB server using `absfs/smbfs` backed by an in-memory filesystem (`absfs/memfs`).

## Features

- **In-memory filesystem**: Uses `memfs` for a complete filesystem entirely in memory
- **Sample content**: Pre-populated with directories and files
- **Guest access**: Anonymous access enabled for easy testing
- **Graceful shutdown**: Proper signal handling for SIGINT/SIGTERM
- **Configurable**: Command-line flags for port, share name, and more
- **Cross-platform clients**: Works with Windows, macOS, and Linux clients

## Building

```bash
go build -o smb-server .
```

## Running

### Basic usage

```bash
# Start server on port 4450 (default)
./smb-server

# Custom port and share name
./smb-server -port 8445 -share data

# Read-only mode
./smb-server -readonly

# Enable debug logging
./smb-server -debug
```

### Command-line options

- `-port int`: Port to listen on (default: 4450, to avoid needing root)
- `-share string`: Share name (default: "myshare")
- `-host string`: Hostname/IP to bind to (default: "0.0.0.0")
- `-readonly`: Export share as read-only
- `-debug`: Enable debug logging

## Connecting to the Server

### macOS/Linux using smbclient

```bash
smbclient //localhost/myshare -p 4450 -U guest -N
```

Once connected, you can use standard SMB commands:
```
smb: \> ls
smb: \> cd documents
smb: \> get README.txt
smb: \> put myfile.txt
smb: \> quit
```

### macOS Finder

1. Open Finder
2. Press `Command-K` (Go > Connect to Server)
3. Enter: `smb://guest@localhost:4450/myshare`
4. Click "Connect"

### Windows

Open PowerShell as Administrator:

```powershell
net use X: \\localhost@4450\myshare /user:guest ""
```

To disconnect:
```powershell
net use X: /delete
```

### Linux mount

```bash
sudo mount -t cifs //localhost/myshare /mnt/share -o port=4450,guest,username=guest
```

To unmount:
```bash
sudo umount /mnt/share
```

### Using absfs/smbfs (Go code)

```go
package main

import (
    "fmt"
    "log"

    "github.com/absfs/smbfs"
)

func main() {
    fs, err := smbfs.New(&smbfs.Config{
        Server:      "localhost",
        Port:        4450,
        Share:       "myshare",
        GuestAccess: true,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer fs.Close()

    // List files
    entries, err := fs.ReadDir("/")
    if err != nil {
        log.Fatal(err)
    }

    for _, entry := range entries {
        fmt.Println(entry.Name())
    }
}
```

## Sample Content

The server creates the following directory structure:

```
/
├── README.txt
├── documents/
│   ├── report.txt
│   ├── reports/
│   │   └── q1-2024.txt
│   └── presentations/
│       └── demo.txt
├── photos/
│   ├── README.txt
│   └── vacation/
│       └── itinerary.txt
├── music/
│   └── playlist.txt
└── empty/
```

## Code Walkthrough

The example demonstrates the following steps:

### 1. Creating an in-memory filesystem

```go
fs, err := memfs.NewFS()
if err != nil {
    log.Fatal(err)
}
```

### 2. Populating with sample files

```go
// Create directories
fs.MkdirAll("/documents/reports", 0755)

// Create files with content
file, _ := fs.Create("/README.txt")
file.Write([]byte("Welcome to SMB!"))
file.Close()
```

### 3. Configuring the SMB server

```go
serverOpts := smbfs.ServerOptions{
    Port:     4450,
    Hostname: "0.0.0.0",
    Debug:    false,
}

server, err := smbfs.NewServer(serverOpts)
```

### 4. Adding a share

```go
shareOpts := smbfs.ShareOptions{
    ShareName:  "myshare",
    SharePath:  "/",
    ReadOnly:   false,
    AllowGuest: true,
    Comment:    "Example in-memory share",
}

server.AddShare(fs, shareOpts)
```

### 5. Starting the server

```go
if err := server.Listen(); err != nil {
    log.Fatal(err)
}
```

### 6. Graceful shutdown

```go
sigChan := make(chan os.Signal, 1)
signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

go func() {
    <-sigChan
    server.Stop()
}()
```

## Notes

- **In-memory**: All data is stored in memory and will be lost when the server stops
- **Guest access**: This example allows anonymous guest access for simplicity. In production, configure proper authentication
- **Port**: Default port 4450 is used to avoid requiring root/administrator privileges (standard SMB port 445 requires elevated privileges)
- **Testing**: Perfect for development, testing, and demonstrations
- **Production**: For production use, consider:
  - Proper authentication (username/password, Kerberos)
  - TLS/encryption
  - Access controls and IP restrictions
  - Persistent storage (use `osfs`, `s3fs`, etc. instead of `memfs`)
  - Logging and monitoring

## Troubleshooting

### "Address already in use"
Another process is using the port. Try a different port:
```bash
./smb-server -port 4451
```

### "Permission denied" on port 445
Standard SMB port requires root/administrator. Use a higher port (> 1024):
```bash
./smb-server -port 4450
```

### Cannot connect from client
- Check firewall settings
- Ensure server is listening on the correct interface (`-host 0.0.0.0`)
- Try connecting from localhost first

### Windows "Network path not found"
Windows may need SMB version compatibility adjustments. Try:
- Using the IP address instead of hostname
- Enabling SMB2/SMB3 in Windows features
- Running as Administrator

## See Also

- [Basic Example](../basic/) - Connect to an SMB share (client)
- [Advanced Example](../advanced/) - Advanced client configuration
- [absfs](https://github.com/absfs/absfs) - Abstract filesystem interface
- [memfs](https://github.com/absfs/memfs) - In-memory filesystem
