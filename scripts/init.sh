if [[ $(cargo --version) ]]; then
    echo "Found cargo"
else
    curl https://sh.rustup.rs -sSf | sh -s -- -y
    source $HOME/.cargo/env
    export PATH=$HOME/.cargo/bin:$PATH
fi

sudo add-apt-repository ppa:ethereum/ethereum
sudo apt-get update
cargo install svm-rs && svm install 0.8.17