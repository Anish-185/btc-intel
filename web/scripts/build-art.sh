#!/usr/bin/env bash
# Rebuild web/public/art/*.png from the reference sheet.
#
# Each output is a small greyscale "ink map": white where the picture should
# be drawn, black where it should not. The console never shows these files as
# images. src/components/DotArt.tsx samples them and draws its own dots or
# glyphs in the theme's colours, so one file serves both themes.
#
#   scripts/build-art.sh ~/front
set -euo pipefail
SRC="${1:?usage: build-art.sh <reference dir>}"
OUT="$(cd "$(dirname "$0")/.." && pwd)/public/art"
mkdir -p "$OUT"

# name  source  crop(WxH+X+Y or "-")  invert(0/1)  width  levels  [blur]
# Keep sources larger than they are drawn: DotArt box-averages them down.
art() {
  local name="$1" file="$2" crop="$3" inv="$4" w="$5" lv="$6" blur="${7:-}"
  local args=("$SRC/$file[0]")
  [ "$crop" != "-" ] && args+=(-crop "$crop" +repage)
  args+=(-alpha off -colorspace Gray)
  [ "$inv" = 1 ] && args+=(-negate)
  [ -n "$blur" ] && args+=(-blur "$blur")
  args+=(-level "$lv" -resize "${w}x" -strip -define png:color-type=0 "$OUT/$name.png")
  magick "${args[@]}"
}

art hero      "Timeless and powerful.jpeg"              736x330+0+300    0 368 "45%,95%"
# The picture's own emblem sits between the fingertips; our spark goes there.
magick "$OUT/hero.png" -fill black -draw "rectangle 158,52 208,102" "$OUT/hero.png"
art ingest    "technology wallpaper.jpeg"               736x736+0+120    0 120 "10%,75%"
art cluster   "_ (3).jpeg"                              -                0 360 "30%,95%"
art detect    "Réseaux.jpeg"                            -                1 360 "5%,60%"
art taint     "pressure print.jpeg"                     -                1 180 "10%,85%"
art origin    "Poplr Inc_ - Allan Revah.gif"            -                0 150 "27%,45%" 0x6
art validity  "_ (1).jpeg"                              736x700+0+0      0 160 "55%,100%"
art exits     "Found on Cosmos.jpeg"                    736x860+0+60     0 200 "45%,95%"
art custody   "_.jpeg"                                  700x1000+18+300  0 240 "15%,80%"
art redteam   "_ (2).jpeg"                              -                0 240 "35%,95%"
art capital   "Gemini_Generated_Image_k4asq0k4asq0k4as.png" 840x1416+1540+120 1 260 "2%,85%"
ls -la "$OUT"
