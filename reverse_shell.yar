rule PythonReverseShell {
    strings:
        $s1 = "socket.socket" ascii wide
        $s2 = "os.dup2" ascii wide
        $s3 = "pty.spawn" ascii wide
        $s4 = "/bin/bash" ascii wide
    condition:
        3 of ($s1, $s2, $s3, $s4)
}
