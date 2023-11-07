package webtwo

import (
	"embed"
	_ "embed"
	"net/http"
)

//go:embed robots.txt
var RobotsTxt []byte

//go:embed dist/index.html
var IndexByte []byte

//go:embed dist/*
var StaticDist embed.FS

//go:embed security.txt
var SecurityTxt []byte

var StaticHandler = http.FileServer(http.Dir("./webtwo/dist/"))
