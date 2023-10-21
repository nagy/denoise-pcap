{ root, self, flake-self, pkgs, lib, callPackage, system, runCommandLocal
, ghostscript, imagemagick, optipng, drawio-headless, pdftk, nixos-lib }:

{
  pdftopng = file:
    runCommandLocal "pages" {
      nativeBuildInputs = [ ghostscript imagemagick optipng ];
    } ''
      mkdir $out ; cd $out
      magick -density 300 ${file} -alpha remove pages.png
      optipng -strip all *.png
    '';
  convert = file: command:
    runCommandLocal "converted.png" {
      nativeBuildInputs = [ imagemagick optipng ];
      theCommand = command
        ++ [ "-trim" "-bordercolor white" "-border 50" "-delete 1--1" ];
    } ''
      magick convert ${file} $theCommand $out
      optipng -strip all $out
    '';

  drawiotopdf = { file, layers ? "", page ? null }:
    runCommandLocal "drawio.pdf" {
      nativeBuildInputs = [ drawio-headless ]
        ++ (lib.optional (page != null) pdftk);
    } ''
      drawio \
        ${if layers != "" then "--layers ${layers}" else ""} \
        --crop --export --uncompressed --scale 4 \
        --output $out \
        ${file}
      ${if page != null then ''
        mv $out file.pdf
        pdftk file.pdf cat ${toString page} output $out
      '' else
        ""}
    '';

  overviewMethod = ../overview_method.drawio;

  evaluation = ../evaluation.drawio;

  testEnvMap = lib.mapAttrs' (name: value:
    lib.nameValuePair
    ("TEST_" + (lib.toUpper (lib.replaceStrings [ "-" ] [ "_" ] name)))
    (root.mkEnrichedTest value)) root.tests;

}
