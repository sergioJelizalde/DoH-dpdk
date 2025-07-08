#!/bin/sh

# Add Mellanox DOCA pkg-config path
sudo export PKG_CONFIG_PATH=${PKG_CONFIG_PATH}:/opt/mellanox/doca/lib/aarch64-linux-gnu/pkgconfig

# Add Mellanox DOCA tools to PATH
sudo export PATH=${PATH}:/opt/mellanox/doca/tools

# Add Mellanox DPDK pkg-config path
sudo export PKG_CONFIG_PATH=${PKG_CONFIG_PATH}:/opt/mellanox/dpdk/lib/aarch64-linux-gnu/pkgconfig

# Add Mellanox FlexIO pkg-config path
sudo export PKG_CONFIG_PATH=${PKG_CONFIG_PATH}:/opt/mellanox/flexio/lib/pkgconfig

# Add DPDK include pkg-config path
sudo export PKG_CONFIG_PATH=${PKG_CONFIG_PATH}:/opt/mellanox/dpdk/include/aarch64-linux-gnu/dpdk

echo "Environment configured."
