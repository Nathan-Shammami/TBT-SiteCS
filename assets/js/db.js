import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm";
import { SUPABASE_URL, SUPABASE_ANON_KEY, aesKey } from "./config.js";

// Initialize Supabase
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// AES Encryption Function
async function encrypt(text, key) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);

    // Check if the key is a valid Uint8Array
    if (!(key instanceof Uint8Array)) {
        throw new Error('Key is not a valid Uint8Array');
    }

    // Ensure the key is 16 bytes (for AES-128)
    if (key.length !== 16) {
        throw new Error('Key must be 16 bytes for AES-128 encryption');
    }

    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key,  // Use the key directly
        { name: "AES-GCM" },
        false,
        ["encrypt"]
    );

    const iv = crypto.getRandomValues(new Uint8Array(12)); // 12-byte IV for AES-GCM
    const encryptedData = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        data
    );

    return {
        encrypted: btoa(String.fromCharCode(...new Uint8Array(encryptedData))),
        iv: btoa(String.fromCharCode(...iv))
    };
}

// AES Decryption Function
async function decrypt(encrypted, iv, key) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key,  
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );

    const ivBytes = Uint8Array.from(atob(iv), c => c.charCodeAt(0));
    const encryptedBytes = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));

    const decryptedData = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivBytes},
        cryptoKey,
        encryptedBytes
    );

    return new TextDecoder().decode(decryptedData);
}

// Save Encrypted Email to Supabase
async function saveEmail(email) {
    const keyArray = new Uint8Array(atob(aesKey).split("").map(c => c.charCodeAt(0)));

    const { encrypted, iv } = await encrypt(email, keyArray);

    const { data, error } = await supabase
        .from("email")
        .insert([{ email_address: encrypted, iv: iv, created_at: new Date()}]);
        console.log("email added!")
    if (error) {
        console.error("Error saving email:", error);
    } else {
        console.log("Email saved:", data);
    }
    
    const { data: session, sessionerror } = await supabase.auth.getSession();
        if (error) {
            console.log('Error fetching session:', error.message);
        }
        if (session) {
            console.log('User is logged in:', session.user);
        }
}

export { encrypt, decrypt, saveEmail };
