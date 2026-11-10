package main

import (
	"fmt"
	"os"
	"strings"
)

// runCompletion implements `ptctl completion <shell>`: it prints a static
// shell-completion script for bash, zsh, or fish. The scripts complete the
// subcommand names and the common global flags. They are static (no runtime
// proxy calls), so they work offline and load instantly.
func runCompletion(args []string) error {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: ptctl completion bash|zsh|fish")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  ptctl completion bash > /etc/bash_completion.d/ptctl")
		fmt.Fprintln(os.Stderr, "  ptctl completion zsh  > \"${fpath[1]}/_ptctl\"")
		fmt.Fprintln(os.Stderr, "  ptctl completion fish > ~/.config/fish/completions/ptctl.fish")
		return fmt.Errorf("exactly one shell argument is required")
	}
	cmds := strings.Join(commandNames(), " ")
	flags := "--url --tenant --token --admin-prefix --insecure --timeout"
	switch args[0] {
	case "bash":
		fmt.Print(bashCompletion(cmds, flags))
	case "zsh":
		fmt.Print(zshCompletion(cmds))
	case "fish":
		fmt.Print(fishCompletion())
	default:
		return fmt.Errorf("unsupported shell %q (want: bash, zsh, or fish)", args[0])
	}
	return nil
}

func bashCompletion(cmds, flags string) string {
	return `# bash completion for ptctl
_ptctl() {
    local cur prev words cword
    _init_completion 2>/dev/null || {
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
    }
    local commands="` + cmds + `"
    local globals="` + flags + `"
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "${commands}" -- "${cur}") )
        return 0
    fi
    case "$prev" in
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "${cur}") )
            return 0
            ;;
    esac
    COMPREPLY=( $(compgen -W "${globals}" -- "${cur}") )
}
complete -F _ptctl ptctl
`
}

func zshCompletion(cmds string) string {
	return `#compdef ptctl
# zsh completion for ptctl
_ptctl() {
    local -a commands
    commands=(` + zshCommandList() + `)
    _arguments -C \
        '1: :->command' \
        '*:: :->args' \
        '--url[proxy base URL]:url:' \
        '--tenant[tenant scope]:tenant:' \
        '--token[proxy access token]:token:' \
        '--admin-prefix[admin API prefix]:prefix:' \
        '--insecure[skip TLS verification]' \
        '--timeout[per-request timeout]:duration:'
    case "$state" in
        command) _describe 'command' commands ;;
        args)
            case "$line[1]" in
                completion) _values 'shell' bash zsh fish ;;
            esac
            ;;
    esac
}
_ptctl "$@"
`
}

// zshCommandList renders the subcommands as zsh "name:summary" describe entries.
func zshCommandList() string {
	parts := make([]string, 0)
	for _, c := range commands() {
		parts = append(parts, fmt.Sprintf("'%s:%s'", c.name, c.summary))
	}
	return strings.Join(parts, " ")
}

func fishCompletion() string {
	var b strings.Builder
	b.WriteString("# fish completion for ptctl\n")
	b.WriteString("complete -c ptctl -f\n")
	for _, c := range commands() {
		fmt.Fprintf(&b, "complete -c ptctl -n __fish_use_subcommand -a %s -d %q\n", c.name, c.summary)
	}
	b.WriteString("complete -c ptctl -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'\n")
	for _, f := range []struct{ name, desc string }{
		{"url", "proxy base URL"},
		{"tenant", "tenant scope"},
		{"token", "proxy access token"},
		{"admin-prefix", "admin API prefix"},
		{"insecure", "skip TLS verification"},
		{"timeout", "per-request timeout"},
	} {
		fmt.Fprintf(&b, "complete -c ptctl -l %s -d %q\n", f.name, f.desc)
	}
	return b.String()
}
