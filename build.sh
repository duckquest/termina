echo "Start..."
git_dir=$(dirname "$0")
src_dir=$git_dir/ipxe/src
echo "Entering '$src_dir'..."
cd $src_dir

echo "Building..."
make bin/8086100f.mrom bin/808610d3.mrom bin/10222000.rom bin/15ad07b0.rom bin/ipxe.usb bin/ipxe.iso

echo "Copying..."
cp bin/8086100f.mrom bin/808610d3.mrom bin/10222000.rom bin/15ad07b0.rom bin/ipxe.usb bin/ipxe.iso ../../
