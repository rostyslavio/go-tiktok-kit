# TikTok Kit for Go
Docs: https://developers.tiktok.com/doc/login-kit-web
## Installation
```shell
go get -u github.com/rostyslavio/go-tiktok-kit
```
## TikTok Documentation
- Login Kit for Web  
https://developers.tiktok.com/doc/login-kit-web

- Share Sound  
https://developers.tiktok.com/doc/sound-kit-share-sound

- Share Video  
https://developers.tiktok.com/doc/web-video-kit-with-web

[comment]: <> (- Embed Videos  )

[comment]: <> (https://developers.tiktok.com/doc/embed-videos)

[comment]: <> (- Webhooks  )

[comment]: <> (https://developers.tiktok.com/doc/webhooks-overview)

## Examples
```go
package main

import (
	ttkit "github.com/rostyslavio/go-tiktok-kit"
	"log"
)

func main() {
	kit, _ := ttkit.NewTikTokKit(
	  ttkit.WithClientKey("CLIENT_KEY"),
	  ttkit.WithRedirectUri("https://github.com/rostyslavio/go-tiktok-kit"),
	)

	state := "RANDOM_STRING"

	uri, _ := kit.GetAuthorizeRedirect([]string{ttkit.TikTokReadProfileScope}, state)

	log.Println(uri);

	//log.Printf(redirect)
}
```

## Licence
This package is licensed under the MIT license. See LICENSE for details.
