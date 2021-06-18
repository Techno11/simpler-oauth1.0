export default interface OAuth1Headers {
    consumer_key: string,
    consumer_secret: string,
    token?: string,
    token_secret?: string,
    callback?: string,
    nonce?: string,
    signature_method?: "HMAC-SHA1",
    timestamp?: string,
    verifier?: string,
    version?: "1.0"
}
