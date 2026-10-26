rule PythonReverseShell {
    strings:
        $s1 = "socket.socket" ascii wide
        $s2 = "os.dup2" ascii wide
        $s3 = "pty.spawn" ascii wide
        $s4 = "/bin/bash" ascii wide
        $s5 = "pty.fork" ascii wide
    condition:
        3 of ($s1, $s2, $s3, $s4) or
        all of ($s1, $s4, $s5)
}
