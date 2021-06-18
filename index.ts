import OAuth1Headers from "./OAuth1Headers";
const hmac = require('./HMACSha1')

/**
 * Simpler OAuth: A Back-to-Basics approach to OAuth1.0
 *
 * Currently Only Supports HMAC-SHA1 Signing
 *
 * Adapted from Ben Olson simple-oauth-js: https://github.com/bseth99/simple-oauth-js
 * Adapted from Ruby Gem simple_oauth: https://github.com/laserlemon/simple_oauth
 * Adapted from OAuthSimple: http://unitedHeroes.net/OAuthSimple
 */

class SimplerOAuth1 {
    private data: { [key: string]: any };
    private url: string;
    private method: string;
    private extras: { [key: string]: any } | undefined;

    constructor(url: string, method: string, oauthData: OAuth1Headers, extraParams?: { [key: string]: any }) {
        const defaultOpts = {
            nonce: this.getNonce(),
            signature_method: 'HMAC-SHA1',
            timestamp: '' + Math.floor(new Date().getTime() / 1000),
            version: '1.0'
        }
        this.data = {...defaultOpts, ...oauthData};
        this.url = url;
        this.method = method.toUpperCase();
        this.extras = extraParams;
    }

    /**
     * Builds an OAuth String
     */
    public build(): string {

        // Concatenate all of our oauth options (URL parameters, oauth parameters, and any 'extra' parameters
        const signatureBase = this.calcSignatureBase();
        console.log(signatureBase)
        // Generate a signature from all of our signed keys
        const signature = this.getSignature( signatureBase );
        // Generate an object of our OAuth Attributes
        const signedAttributes = this.signedAttributes(signature);
        // Generate our OAuth header string
        const oauthString = this.normalizeAttributes(', ', signedAttributes, '"', '"');

        return `OAuth ${oauthString}`;
    }

    /**
     * Get an object of oauth attributes, which are signed
     * @param signature Signed oauth Signature
     * @private
     */
    private signedAttributes(signature: string): {[key: string]: any} {
        const res = this.oauthifyAttributes();
        res['oauth_signature'] = signature;
        return res;
    }

    /**
     * Append 'oauth_' to our attribute keys
     * @private
     */
    private oauthifyAttributes(): any {
        const res = {} as any;
        Object.keys(this.data).forEach((key: string) => {
            res[`oauth_${key}`] = this.data[key];
        })
        return res;
    }

    /**
     * Generates a Nonce string of a specified length
     * @param length
     * @private
     */
    private getNonce(length: number = 16): string {
        const NONCE_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let result = '';

        for (let i = 0; i < length; i++) {
            const n = Math.floor(Math.random() * NONCE_CHARS.length);
            result += NONCE_CHARS.substring(n, n + 1);
        }

        return result;
    }

    /**
     * Escapes string
     * @param val
     * @private
     */
    private escape(val: string) {
        return encodeURIComponent(val)
            .replace(/\!/g, "%21")
            .replace(/\*/g, "%2A")
            .replace(/'/g, "%27")
            .replace(/\(/g, "%28")
            .replace(/\)/g, "%29");
    }

    /**
     * Convert an object into an escaped, concatenated string
     * @param joinString String to join with
     * @param attributes attributes to parse, sort, and join
     * @param startChar when joining values, the opening encapsulation character.
     * @param endChar when joining values, the closing encapsulation character.
     * @private
     */
    private normalizeAttributes(joinString: string, attributes: any, startChar: string, endChar: string): string {
        const components = [] as any[]
        Object.keys(attributes).forEach((key) => {
            if(attributes[key]) components.push(key + `=${startChar}` + this.escape(attributes[key]) + endChar);
        })
        return components.sort().join(joinString);
    }

    /**
     * Concatenate all of our singable oauth parameters
     * @private
     */
    private calcSignatureBase() {
        const url = new URL(this.url);
        // Base parameters
        let params = { ...this.oauthifyAttributes(), ...this.extras } as any;
        // Get parameters from query string
        url.searchParams.forEach((value: string, key: string) =>  params[key] = value);
        // Normalize string
        const normalized = this.normalizeAttributes('&', params, '', '');
        // Remove all search params
        url.search = '';
        // Join our strings
        return [ this.method, url.toString(), normalized ].join('&');
    }

    /**
     * Generate an hmac sha1 signature
     * @param signatureBase keys to be signed
     * @private
     */
    private getSignature(signatureBase: any) {
        const cs = this.data.consumer_secret ?? '';
        const ts = this.data.token_secret ?? '';
        const secret = `${this.escape(cs)}&${this.escape(ts)}`

        return hmac.b64_hmac_sha1(secret, signatureBase);
    }
}
