# SofthouseChara-Aoi-Tools
Tools for anyone trying to work on a SofthouseChara Aoi Engine game (each game needs to change some settings regarding the Box/VFS files though)

## Extracting VFS files:
> python aoi_vfs_cli.py vfs-extract --vfs box.vfs --name ev0000.box --outdir outfolder

> python aoi_vfs_cli.py vfs-extract --vfs box.vfs --outdir out_all

## Extraacting Box files:
1) Extract+decrypt .box file
> python aoi_cli_v3.py box-extract --box ev0000.box --name ev0002.txt --out ev0002.dec

2) Dump the bank
> python aoi_cli_v3.py bank-export --input ev0002.dec --out ev0002_bank.tsv

3) Edit ev0002_bank.tsv (UTF-8). Keep the first TWO columns (offset, len) unchanged; edit only TEXT.

4) Repack with longer lines allowed (rewrites pointers), then encrypt + repack .box
> python aoi_cli_v3.py bank-repack  --input ev0002.dec --tsv ev0002_bank.tsv --out ev0002_new.dec

> python aoi_cli_v3.py encrypt      --input ev0002_new.dec --out ev0002_new.enc

> python aoi_cli_v3.py box-replace  --box ev0000.box --name ev0002.txt --input ev0002_new.enc --out ev0000_patched.box

Does this work? I don't know yet, I'm still trying to get the scripts dumped perfectly with all the commands intact, you can try though.

## IPH Image handling
Garbro can batch dump the iph files into pngs if you need to see what each iph file is. https://github.com/crskycode/GARbro .

Copy the iph_image_tools.exe and ipf33.dll inside the folder where you will work with the iph/png files and then run a command prompt on the executable though there with either these commands:
> iph_image_tools.exe iph2png test_image.iph

> iph_image_tools.exe png2iph edited_image.png
