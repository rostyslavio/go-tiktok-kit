package ttkit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	authorizeRedirect = "https://www.tiktok.com/auth/authorize/client_key=%s&response_type=code&scope=%s&redirect_uri=%s&state=%s"
	accessTokenEndpoint = "https://open-api.tiktok.com/oauth/access_token/?client_key=%s&client_secret=%s&code=%s&grant_type=authorization_code"
	refreshAccessTokenEndpoint = "https://open-api.tiktok.com/oauth/refresh_token/?client_key=%s&grant_type=refresh_token&refresh_token=%s"
	revokeAccessEndpoint = "https://open-api.tiktok.com/oauth/revoke/?open_id=%s&access_token=%s"
	userInfoEndpoint = "https://open-api.tiktok.com/user/info/"
	videoListEndpoint = "https://open-api.tiktok.com/video/list/"
	videoQueryEndpoint = "https://open-api.tiktok.com/video/query/"
	shareSoundEndpoint = "https://open-api.tiktok.com/share/sound/upload/?open_id=%s&access_token=%s"
	shareVideoEndpoint = "https://open-api.tiktok.com/share/video/upload/?open_id=%s&access_token=%s"

	// TikTokReadProfileScope Read your profile info (avatar, display name).
	TikTokReadProfileScope = "user.info.basic"
	// TikTokReadVideosScope Read your public videos on TikTok.
	TikTokReadVideosScope = "video.list"
	// TikTokShareSoundScope Share your original sound to TikTok.
	TikTokShareSoundScope = "share.sound.create"
	// TikTokShareVideoScope Publish videos to TikTok.
	TikTokShareVideoScope = "video.upload"
)

// TikTokKit is the main struct of the package
type TikTokKit struct {
	Settings *Settings
}

// A TikTokKitOption is an option for TikTokKit
type TikTokKitOption interface {
	Apply(*Settings)
}

type Settings struct {
	ClientKey string
	ClientSecret string
	RedirectUri string
	OpenId string
	AccessToken string
}

// ClientKey
type withClientKey string

func (w withClientKey) Apply(o *Settings) {
	o.ClientKey = string(w)
}

func WithClientKey(clientKey string) TikTokKitOption {
	return withClientKey(clientKey)
}

// ClientSecret
type withClientSecret string

func (w withClientSecret) Apply(o *Settings) {
	o.ClientSecret = string(w)
}

func WithClientSecret(clientSecret string) TikTokKitOption {
	return withClientSecret(clientSecret)
}

// RedirectUri
type withRedirectUri string

func (w withRedirectUri) Apply(o *Settings) {
	o.RedirectUri = string(w)
}

func WithRedirectUri(redirectUri string) TikTokKitOption {
	return withRedirectUri(redirectUri)
}

// OpenId
type withOpenId string

func (w withOpenId) Apply(o *Settings) {
	o.OpenId = string(w)
}

func WithOpenId(openId string) TikTokKitOption {
	return withOpenId(openId)
}

// AccessToken
type withAccessToken string

func (w withAccessToken) Apply(o *Settings) {
	o.AccessToken = string(w)
}

func WithAccessToken(accessToken string) TikTokKitOption {
	return withAccessToken(accessToken)
}

// NewTikTokKit Create new kit
func NewTikTokKit(options ...TikTokKitOption) (*TikTokKit, error) {
	settings, err := ApplySettings(options)
	if err != nil {
		return nil, err
	}

	return &TikTokKit{Settings: settings}, nil
}

func ApplySettings(options []TikTokKitOption) (*Settings, error) {
	var setting Settings

	for _, option := range options {
		option.Apply(&setting)
	}

	return &setting, nil
}

// GetAuthorizeRedirect
// https://developers.tiktok.com/doc/login-kit-web
// Scopes: user.info.basic, video.list, share.sound.create, video.upload
func (kit *TikTokKit) GetAuthorizeRedirect(scopes []string, state string) (uri string, err error) {
	return fmt.Sprintf(authorizeRedirect, kit.Settings.ClientKey, strings.Join(scopes, ","), kit.Settings.RedirectUri, state), nil
}

// GetAccessToken
// https://developers.tiktok.com/doc/login-kit-manage-user-access-tokens
func (kit *TikTokKit) GetAccessToken(code string) (response string, err error) {
	endpoint := fmt.Sprintf(accessTokenEndpoint, kit.Settings.ClientKey, kit.Settings.ClientSecret, code)

	client := &http.Client{}

	r, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(url.Values{}.Encode()))

	if err != nil {
		return "", err
	}

	resp, err := client.Do(r)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	return string(body), nil
}

// RefreshAccessToken
// https://developers.tiktok.com/doc/login-kit-manage-user-access-tokens
func (kit *TikTokKit) RefreshAccessToken() (response string, err error) {
	endpoint := fmt.Sprintf(refreshAccessTokenEndpoint, kit.Settings.ClientKey, kit.Settings.AccessToken)

	client := &http.Client{}

	r, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(url.Values{}.Encode()))

	if err != nil {
		return "", err
	}

	resp, err := client.Do(r)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	return string(body), nil
}

// RevokeAccess
// https://developers.tiktok.com/doc/login-kit-manage-user-access-tokens
func (kit *TikTokKit) RevokeAccess() (response string, err error) {
	endpoint := fmt.Sprintf(revokeAccessEndpoint, kit.Settings.OpenId, kit.Settings.AccessToken)

	client := &http.Client{}

	r, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(url.Values{}.Encode()))

	if err != nil {
		return "", err
	}

	resp, err := client.Do(r)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	return string(body), nil
}

type UserInfoFormData struct {
	AccessToken string `json:"access_token"`
	OpenId string `json:"open_id"`
	Fields []string `json:"fields"`
}

// GetUserInfo
// https://developers.tiktok.com/doc/login-kit-user-info-basic
func (kit *TikTokKit) GetUserInfo(fields []string) (response string, err error) {
	userInfoFormData := UserInfoFormData{
		AccessToken: kit.Settings.AccessToken,
		OpenId: kit.Settings.OpenId,
		Fields: fields,
	}

	postBody, err := json.Marshal(userInfoFormData)

	if err != nil {
		return "", err
	}

	resp, err := http.Post(userInfoEndpoint, "application/json", bytes.NewBuffer(postBody))

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	return string(body), nil
}

type VideoListFormData struct {
	AccessToken string `json:"access_token"`
	OpenId string `json:"open_id"`
	Cursor int64 `json:"cursor"`
	MaxCount int32 `json:"max_count"`
	Fields []string  `json:"fields"`
}

// GetVideoList
// https://developers.tiktok.com/doc/login-kit-video-list
func (kit *TikTokKit) GetVideoList(cursor int64, maxCount int32, fields []string) (response string, err error) {
	videoListFormData := VideoListFormData{
		AccessToken: kit.Settings.AccessToken,
		OpenId: kit.Settings.OpenId,
		Cursor: cursor,
		MaxCount: maxCount,
		Fields: fields,
	}

	postBody, err := json.Marshal(videoListFormData)

	if err != nil {
		return "", err
	}

	resp, err := http.Post(videoListEndpoint, "application/json", bytes.NewBuffer(postBody))

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	return string(body), nil
}

type VideoQueryFormData struct {
	AccessToken string `json:"access_token"`
	OpenId string `json:"open_id"`
	Filters Filters `json:"filters"`
	Fields []string `json:"fields"`
}

type Filters struct {
	VideoIds []string `json:"video_ids"`
}

// GetVideoQuery
// https://developers.tiktok.com/doc/login-kit-video-query
func (kit *TikTokKit) GetVideoQuery(videoIds []string, fields []string) (response string, err error) {
	videoListFormData := VideoQueryFormData{
		AccessToken: kit.Settings.AccessToken,
		OpenId: kit.Settings.OpenId,
		Filters: Filters{
			VideoIds: videoIds,
		},
		Fields: fields,
	}

	postBody, err := json.Marshal(videoListFormData)

	if err != nil {
		return "", err
	}

	resp, err := http.Post(videoQueryEndpoint, "application/json", bytes.NewBuffer(postBody))

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	return string(body), nil
}

// ShareSound
// https://developers.tiktok.com/doc/sound-kit-share-sound
func (kit *TikTokKit) ShareSound(filePath string) (response string, err error) {
	file, err := os.Open(filePath)

	if err != nil {
		return "", err
	}

	defer file.Close()

	endpoint := fmt.Sprintf(shareSoundEndpoint, kit.Settings.OpenId, kit.Settings.AccessToken)
	requestBody := &bytes.Buffer{}
	writer := multipart.NewWriter(requestBody)
	part, err := writer.CreateFormFile("sound_file", filepath.Base(file.Name()))

	if err != nil {
		return "", err
	}

	io.Copy(part, file)
	writer.Close()

	r, err := http.NewRequest("POST", endpoint, requestBody)

	if err != nil {
		return "", err
	}

	r.Header.Add("Content-Type", writer.FormDataContentType())
	client := &http.Client{}

	resp, err := client.Do(r)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	return string(body), nil
}

// ShareVideo
// https://developers.tiktok.com/doc/web-video-kit-with-web
func (kit *TikTokKit) ShareVideo(filePath string) (response string, err error) {
	file, err := os.Open(filePath)

	if err != nil {
		return "", err
	}

	defer file.Close()

	endpoint := fmt.Sprintf(shareVideoEndpoint, kit.Settings.OpenId, kit.Settings.AccessToken)
	requestBody := &bytes.Buffer{}
	writer := multipart.NewWriter(requestBody)
	part, err := writer.CreateFormFile("video", filepath.Base(file.Name()))

	if err != nil {
		return "", err
	}

	io.Copy(part, file)
	writer.Close()

	r, err := http.NewRequest("POST", endpoint, requestBody)

	if err != nil {
		return "", err
	}

	r.Header.Add("Content-Type", writer.FormDataContentType())
	client := &http.Client{}

	resp, err := client.Do(r)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	return string(body), nil
}
