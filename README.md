# Simpler OAuth1.0
### A back-to-basics approach to OAuth1.0 signature and string generation

#### Why?
A few months ago I struggled to find a typed library for OAuth1.0 authentication.  Eventually I just used decided to use [simple-oauth-js](https://github.com/bseth99/simple-oauthjs).
However, that library was written to be used in the browser.  When I needed a pure-node library for OAuth1.0... I decided to cut my search short and just rewrite it for typescript, simplifying it as much as I could.

#### TODO: 
Support other signature methods


#### References:
- Adapted from Ben Olson simple-oauth-js: https://github.com/bseth99/simple-oauth-js
- Adapted from Ruby Gem simple_oauth: https://github.com/laserlemon/simple_oauth
- Adapted from OAuthSimple: http://unitedHeroes.net/OAuthSimple
- HMAC-SHA1 Signature code adapted from http://pajhome.org.uk/crypt/md5

