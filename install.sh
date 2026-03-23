#!/bin/bash

set -e

REPO="KuuDS/k-ssh-agent"
BINARY_NAME="k-ssh-agent"

CHANNEL="${KSSH_AGENT_CHANNEL:-release}"

print_error() {
    echo "Error: $1" >&2
}

print_info() {
    echo "$1"
}

detect_os() {
    local os
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$os" in
        linux)
            echo "linux"
            ;;
        darwin)
            echo "macos"
            ;;
        *)
            print_error "Unsupported operating system: $os"
            exit 1
            ;;
    esac
}

detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)
            echo "x86_64"
            ;;
        arm64|aarch64)
            echo "aarch64"
            ;;
        *)
            print_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
}

get_asset_name() {
    local os=$1
    local arch=$2
    
    case "$os" in
        macos)
            case "$arch" in
                aarch64)
                    echo "k-ssh-agent-macos-aarch64.tar.gz"
                    ;;
                *)
                    print_error "No prebuilt binary available for macOS $arch"
                    print_info "Currently only macOS aarch64 (Apple Silicon) is supported."
                    print_info "Please build from source: cargo install --git https://github.com/$REPO"
                    exit 1
                    ;;
            esac
            ;;
        linux)
            print_error "No prebuilt binary available for Linux"
            print_info "Please build from source: cargo install --git https://github.com/$REPO"
            exit 1
            ;;
        *)
            print_error "Unsupported OS: $os"
            exit 1
            ;;
    esac
}

get_download_url() {
    local asset_name=$1
    
    if [ "$CHANNEL" = "nightly" ]; then
        echo "https://github.com/$REPO/releases/download/nightly/$asset_name"
    else
        local latest_tag
        latest_tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"tag_name": "([^"]+)".*/\1/')
        if [ -z "$latest_tag" ]; then
            print_error "Failed to get latest release tag"
            exit 1
        fi
        echo "https://github.com/$REPO/releases/download/$latest_tag/$asset_name"
    fi
}

get_install_dir() {
    if [ -n "$KSSH_AGENT_INSTALL_DIR" ]; then
        echo "$KSSH_AGENT_INSTALL_DIR"
    elif [ -d "$HOME/.local/bin" ]; then
        echo "$HOME/.local/bin"
    elif [ -d "$HOME/bin" ]; then
        echo "$HOME/bin"
    else
        mkdir -p "$HOME/.local/bin"
        echo "$HOME/.local/bin"
    fi
}

check_command() {
    local cmd=$1
    if ! command -v "$cmd" &> /dev/null; then
        return 1
    fi
    return 0
}

main() {
    print_info "Installing $BINARY_NAME..."
    print_info "Channel: $CHANNEL"
    
    if ! check_command curl; then
        print_error "curl is required but not installed"
        exit 1
    fi
    
    local os
    os=$(detect_os)
    print_info "Detected OS: $os"
    
    local arch
    arch=$(detect_arch)
    print_info "Detected architecture: $arch"
    
    local asset_name
    asset_name=$(get_asset_name "$os" "$arch")
    print_info "Asset: $asset_name"
    
    local download_url
    download_url=$(get_download_url "$asset_name")
    print_info "Download URL: $download_url"
    
    local temp_dir
    temp_dir=$(mktemp -d)
    trap 'rm -rf "$temp_dir"' EXIT
    
    print_info "Downloading..."
    if ! curl -fsSL "$download_url" -o "$temp_dir/$asset_name"; then
        print_error "Failed to download $asset_name"
        if [ "$CHANNEL" = "nightly" ]; then
            print_info "Nightly build may not be available yet. Try release channel instead:"
            print_info "  KSSH_AGENT_CHANNEL=release curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | bash"
        else
            print_info "The release asset may not be available for your platform."
            print_info "Please build from source: cargo install --git https://github.com/$REPO"
        fi
        exit 1
    fi
    
    print_info "Extracting..."
    cd "$temp_dir"
    if ! tar -xzf "$asset_name"; then
        print_error "Failed to extract archive"
        exit 1
    fi
    
    local extracted_binary
    extracted_binary=$(find . -name "$BINARY_NAME" -type f | head -n 1)
    if [ -z "$extracted_binary" ]; then
        print_error "Could not find binary in archive"
        exit 1
    fi
    
    chmod +x "$extracted_binary"
    
    local install_dir
    install_dir=$(get_install_dir)
    
    if [ ! -d "$install_dir" ]; then
        print_info "Creating install directory: $install_dir"
        mkdir -p "$install_dir"
    fi
    
    local target_path="$install_dir/$BINARY_NAME"
    
    if [ -f "$target_path" ]; then
        print_info "Replacing existing binary at $target_path"
        rm -f "$target_path"
    fi
    
    mv "$extracted_binary" "$target_path"
    
    print_info ""
    print_info "✓ Successfully installed $BINARY_NAME to $target_path"
    print_info ""
    
    if ! echo "$PATH" | tr ':' '\n' | grep -qx "$install_dir"; then
        print_info "Note: $install_dir is not in your PATH"
        print_info "Add the following to your shell configuration file (.bashrc, .zshrc, etc.):"
        print_info ""
        print_info "  export PATH=\"$install_dir:\$PATH\""
        print_info ""
    fi
    
    print_info "Get started with:"
    print_info "  $BINARY_NAME --help"
}

main "$@"
