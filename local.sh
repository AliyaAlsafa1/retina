export PATH_TO_DPDK_DIR=/etinfo/users2/tyunyayev/Workspace/dpdk-stable-24.11.2/install_$(hostname)
export LD_LIBRARY_PATH=$PATH_TO_DPDK_DIR/lib/x86_64-linux-gnu
export PKG_CONFIG_PATH=$LD_LIBRARY_PATH/pkgconfig
export DPDK_PATH=$PATH_TO_DPDK_DIR/install_$(hostname)
export DPDK_VERSION=24.11
