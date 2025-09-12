const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const puppeteer = require('puppeteer');
const dns = require('dns').promises;
const https = require('https');
const fs = require('fs').promises;
const path = require('path');
const nodemailer = require('nodemailer');
const { v2: cloudinary } = require('cloudinary');
// Utilities (will replace inline implementations in future refactor if desired)
let externalImporter=null; let externalEmail=null; try { externalImporter=require('./utils/importer'); externalEmail=require('./utils/email'); } catch{}
const cron = require('node-cron');
const cors = require('cors');
const session = require('express-session');
const multer = require('multer');
const csv = require('csv-parser');
const { Readable } = require('stream');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// ---------------- Configuration ----------------
const PORT = process.env.PORT || 3001;
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const SESSION_SECRET = process.env.SESSION_SECRET || 'change_me_dev';
// Default scan interval now 60 minutes (override with SCAN_INTERVAL_MS env var)
const SCAN_INTERVAL_MS = parseInt(process.env.SCAN_INTERVAL_MS || (60*60*1000),10); // 60 minutes default
const DAILY_CRON = (process.env.DAILY_CRON ? process.env.DAILY_CRON.split('#')[0].trim() : '0 9 * * *');
const SSL_EXPIRING_SOON_DAYS = parseInt(process.env.SSL_EXPIRING_SOON_DAYS || '7',10);
const SCAN_CONCURRENCY = parseInt(process.env.SCAN_CONCURRENCY || '3',10);
// Email credential mapping (strict requirement per spec)
const EMAIL_USER = process.env.GMAIL_USER || '';
const EMAIL_PASS = process.env.GMAIL_PASS || '';
const ALERT_EMAIL = process.env.ALERT_EMAIL || '';

// Cloudinary Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const NAV_TIMEOUT = 25000;
// Faster overall timeouts for new logic
const QUICK_HTTP_TIMEOUT = 6000; // ms for initial lightweight HTTP probe
const PUPPETEER_NAV_TIMEOUT = 12000; // ms for full page load when needed
// Store screenshots in legacy-compatible photos directory (fallback for local dev)
const SCREENSHOT_DIR = path.join(__dirname,'public','photos');
const SCREENSHOT_PUBLIC_PREFIX = '/photos';
const BASE_PUBLIC_URL = process.env.BASE_PUBLIC_URL || `https://backend-q7e0.onrender.com`;
// Allow public (unauthenticated) URL submission + listing if set to '1'
const ALLOW_PUBLIC_SUBMISSION = process.env.ALLOW_PUBLIC_SUBMISSION === '1';

// ---------------- Status & Alerts ----------------
const STATUS = Object.freeze({
  OK:'OK',
  CANCELLED:'CANCELLED',
  DNS_ERROR:'DNS_ERROR',
  TIMEOUT:'TIMEOUT',
  CONNECTION_REFUSED:'CONNECTION_REFUSED',
  HTTP_ERROR:'HTTP_ERROR',
  SSL_MISSING:'SSL_MISSING',
  SSL_EXPIRED:'SSL_EXPIRED',
  SSL_EXPIRING_SOON:'SSL_EXPIRING_SOON',
  SSL_UNTRUSTED:'SSL_UNTRUSTED',
  SSL_MISMATCH:'SSL_MISMATCH',
  SSL_ERROR:'SSL_ERROR',
  MALWARE_OVERLAY:'MALWARE_OVERLAY',
  GAMBLING_OVERLAY:'GAMBLING_OVERLAY',
  BOT_PROTECTION_BLOCKED:'BOT_PROTECTION_BLOCKED',
  ANOMALY_SUSPECTED:'ANOMALY_SUSPECTED'
});
function isErrorStatus(s){ return s && s!==STATUS.OK && s!==STATUS.CANCELLED; }

// ---------------- Alert State (DB based) ----------------
const lastStatusMap = new Map(); // id -> last status for alert diffs

// ---------------- Email Transport (Gmail) ----------------
// Enforce presence of required email vars early
if(!EMAIL_USER || !EMAIL_PASS || !ALERT_EMAIL){
  throw new Error('[EMAIL] Missing required env vars. Need GMAIL_USER, GMAIL_PASS (app password), ALERT_EMAIL');
}
let mailer = nodemailer.createTransport({ service:'gmail', auth:{ user:EMAIL_USER, pass:EMAIL_PASS } });
mailer.verify()
  .then(()=>console.log('[EMAIL] Transport verified'))
  .catch(e=>{ console.error('[EMAIL] Transport verify failed:', e.message); process.exit(1); });
async function sendMail(subject, html){
  try { await mailer.sendMail({ from:EMAIL_USER, to:ALERT_EMAIL, subject, html }); return true; }
  catch(e){ console.error('[EMAIL] send failed', e.message); return false; }
}

function daysUntil(dateIso){ if(!dateIso) return null; const d=new Date(dateIso).getTime(); return Math.ceil((d-Date.now())/86400000); }

// Simple cron descriptor for a few expected patterns
function describeCron(expr){
  try {
    if(!expr) return 'on the defined schedule';
    const parts=expr.trim().split(/\s+/);
    if(parts.length<5) return 'on the defined schedule';
    const [min,hour] = parts;
    if(min==='*/5' && hour==='*') return 'every 5 minutes';
    if(min==='0' && hour==='*') return 'hourly';
    if(min==='0' && /\d+/.test(hour)) return `daily at ${hour.padStart(2,'0')}:00 (server TZ)`;
    return 'on the defined schedule';
  } catch { return 'on the defined schedule'; }
}
// Effective scan cron (default hourly at minute 0)
const EFFECTIVE_SCAN_CRON = (process.env.SCAN_CRON ? process.env.SCAN_CRON.split('#')[0].trim() : '0 * * * *');
const SCAN_FREQUENCY_DESC = describeCron(EFFECTIVE_SCAN_CRON);

async function sendAlertEmail(row, result){
  const days=daysUntil(result.ssl_expires_at);
  const expiryInfo=(result.status==='SSL_EXPIRING_SOON' && days!=null)?` (SSL expiry ${days} days)`:'';
  const subject=`🚨 ALERT: ${row.url} ${result.status}`;
  
  let detailsHtml = '';
  if(result.error_details) detailsHtml += `<p><strong>Error Details:</strong> ${result.error_details}</p>`;
  if(result.ssl_expires_at) detailsHtml += `<p><strong>SSL Expires:</strong> ${result.ssl_expires_at} (${days} days)</p>`;
  if(result.additional_anomalies) detailsHtml += `<p><strong>Anomalies:</strong> ${result.additional_anomalies}</p>`;
  if(result.screenshot_url) detailsHtml += `<p><strong>Screenshot:</strong> <a href="${result.screenshot_url}">View Screenshot</a></p>`;
  
  const statusEmoji = {
    'SSL_EXPIRED': '🔒❌',
    'SSL_EXPIRING_SOON': '🔒⚠️',
    'SSL_UNTRUSTED': '🔒⚠️',
    'SSL_MISMATCH': '🔒⚠️',
    'MALWARE_OVERLAY': '🦠',
    'GAMBLING_OVERLAY': '🎰',
    'TIMEOUT': '⏰',
    'CONNECTION_REFUSED': '🚫',
    'DNS_ERROR': '🌐❌',
    'HTTP_ERROR': '🔗❌'
  };
  
  const emoji = statusEmoji[result.status] || '❌';
  const html=`
    <div style="font-family: Arial, sans-serif; max-width: 600px;">
      <h2>${emoji} Site Alert</h2>
      <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0;">
        <p><strong>URL:</strong> <a href="https://${row.url}" target="_blank">${row.url}</a></p>
        <p><strong>Status:</strong> <span style="color: #dc3545; font-weight: bold;">${result.status}</span></p>
        <p><strong>Detected At:</strong> ${new Date().toLocaleString()}</p>
      </div>
      ${detailsHtml}
      <p style="font-size: 12px; color: #666;">
        This alert will continue at the <strong>${SCAN_FREQUENCY_DESC}</strong> scan frequency until the issue is resolved.
      </p>
    </div>
  `;
  
  const ok=await sendMail(subject, html);
  if(ok) console.log(`[EMAIL] Alert sent to ${ALERT_EMAIL} for site: ${row.url}${expiryInfo}`);
  else console.log(`[EMAIL] Alert failed for site: ${row.url}`);
}

async function sendRecoveryEmail(row, prevStatus){
  const subject=`✅ RECOVERY: ${row.url} back online`;
  const html=`
    <div style="font-family: Arial, sans-serif; max-width: 600px;">
      <h2 style="color: #28a745;">✅ Site Recovery</h2>
      <div style="background: #d4edda; padding: 15px; border-radius: 5px; margin: 10px 0; border: 1px solid #c3e6cb;">
        <p><strong>URL:</strong> <a href="https://${row.url}" target="_blank">${row.url}</a></p>
        <p><strong>Previous Status:</strong> <span style="color: #dc3545;">${prevStatus}</span></p>
        <p><strong>Current Status:</strong> <span style="color: #28a745; font-weight: bold;">OK</span></p>
        <p><strong>Recovered At:</strong> ${new Date().toLocaleString()}</p>
      </div>
      <p>The site is now functioning normally. Monitoring will continue as usual.</p>
    </div>
  `;
  
  const ok=await sendMail(subject, html);
  if(ok) console.log(`[EMAIL] Recovery sent to ${ALERT_EMAIL} for site: ${row.url}`);
  else console.log(`[EMAIL] Recovery send failed for site: ${row.url}`);
}

// ---------------- SSL Inspection ----------------
async function fetchCertificate(host){
  return new Promise(resolve=>{
    const req=https.request({ host, port:443, method:'GET', rejectUnauthorized:false, servername:host, timeout:8000 }, res=>{
      const cert=res.socket.getPeerCertificate();
      req.destroy();
      resolve(cert&&cert.valid_to?cert:null);
    });
    req.on('error',err=>{ if(['ENOTFOUND'].includes(err.code)) return resolve(null); resolve({ error:err }); });
    req.on('timeout',()=>{ req.destroy(); resolve({ timeout:true }); });
    req.end();
  });
}
async function strictVerify(host){
  return new Promise(resolve=>{
    const r=https.request({ host, port:443, method:'GET', rejectUnauthorized:true, servername:host, timeout:7000 }, res=>{ r.destroy(); resolve({ ok:true }); });
    r.on('error',e=>resolve({ ok:false, error:e }));
    r.on('timeout',()=>{ r.destroy(); resolve({ ok:false, timeout:true }); });
    r.end();
  });
}
async function analyzeSSL(host){
  const out={ status:'OK', detail:null, expires:null, issuer:null, algorithm:null, keySize:null };
  const cert=await fetchCertificate(host);
  if(!cert){ out.status='SSL_MISSING'; out.detail='no certificate'; return out; }
  if(cert.error){ out.status='SSL_ERROR'; out.detail=cert.error.code||'handshake error'; return out; }
  if(cert.timeout){ out.status='SSL_ERROR'; out.detail='handshake timeout'; return out; }
  
  if(cert.valid_to){
    const exp=new Date(cert.valid_to); 
    out.expires=exp.toISOString();
    out.issuer=cert.issuer?.CN || cert.issuer?.O || 'Unknown';
    out.algorithm=cert.sigalg || 'Unknown';
    
    const days=(exp.getTime()-Date.now())/86400000;
    if(days<0){ 
      out.status='SSL_EXPIRED'; 
      out.detail=`expired ${Math.abs(Math.ceil(days))} days ago`; 
      return out; 
    }
    
    // Enhanced expiry warnings
    if(days<1){ out.status='SSL_EXPIRED'; out.detail='expires today'; }
    else if(days<7){ out.status='SSL_EXPIRING_SOON'; out.detail=`expires in ${Math.ceil(days)} day(s)`; }
    else if(days<30){ out.status='SSL_EXPIRING_SOON'; out.detail=`expires in ${Math.ceil(days)} days`; }
    
    // Check for weak algorithms
    const weakAlgorithms = ['md5', 'sha1WithRSAEncryption', 'sha1'];
    if(cert.sigalg && weakAlgorithms.some(alg => cert.sigalg.toLowerCase().includes(alg))){
      out.status='SSL_ERROR';
      out.detail='weak signature algorithm';
    }
    
    // Check key size if available
    if(cert.pubkey && cert.pubkey.bits) {
      out.keySize = cert.pubkey.bits;
      if(cert.pubkey.bits < 2048) {
        out.status='SSL_ERROR';
        out.detail='weak key size';
      }
    }
  }
  
  // Enhanced trust verification
  const strict = await strictVerify(host);
  if(!strict.ok){
    const code=(strict.error&&strict.error.code)||'';
    if(/SELF_SIGNED|UNABLE_TO_VERIFY|DEPTH_ZERO_SELF_SIGNED/.test(code)) { 
      out.status='SSL_UNTRUSTED'; 
      out.detail='self-signed/untrusted CA'; 
    }
    else if(/CERT_HAS_EXPIRED/.test(code)) { 
      out.status='SSL_EXPIRED'; 
      out.detail='expired certificate'; 
    }
    else if(/CERT_NOT_YET_VALID/.test(code)) { 
      out.status='SSL_ERROR'; 
      out.detail='certificate not yet valid'; 
    }
    else if(/CERT_REVOKED/.test(code)) { 
      out.status='SSL_ERROR'; 
      out.detail='certificate revoked'; 
    }
    else if(code){ 
      out.status='SSL_ERROR'; 
      out.detail=code; 
    }
    else if(strict.timeout){ 
      out.status='SSL_ERROR'; 
      out.detail='verify timeout'; 
    }
  }
  
  // Enhanced hostname verification
  if(cert.subjectaltname || cert.subject){
    const sans = cert.subjectaltname ? 
      cert.subjectaltname.split(/[, ]+/).filter(x=>x.startsWith('DNS:')).map(x=>x.slice(4).toLowerCase()) : 
      [];
    const cn = cert.subject && cert.subject.CN ? cert.subject.CN.toLowerCase() : '';
    const hostnames = [...sans, cn].filter(Boolean);
    
    const h=host.toLowerCase();
    const match=hostnames.some(hostname => {
      if(hostname === h) return true;
      if(hostname.startsWith('*.')) {
        const domain = hostname.slice(2);
        return h.endsWith('.' + domain) || h === domain;
      }
      return false;
    });
    
    if(!match){ 
      out.status='SSL_MISMATCH'; 
      out.detail=`hostname mismatch (cert: ${hostnames.join(', ')})`; 
    }
  }
  
  return out;
}

// ---------------- Browser / Page Utilities ----------------
let browserPromise=null;
// Global cancellation state for in-progress scans
let cancelRequested = false;
let currentScanGeneration = 0; // increments each new scan or purge
let scanningPaused = false; // pauses cron-triggered scans after purge until explicit run
async function requestCancelAll(){
  cancelRequested = true;
  try {
    if(browserPromise){
      const b = await browserPromise.catch(()=>null);
      if(b){ try { await b.close(); } catch{} }
    }
    // Mark DB rows still in processing/pending as CANCELLED
    try {
      await supabase.from('urls').update({ status: STATUS.CANCELLED }).in('status',['processing','Processing','pending','Pending']);
    } catch(e){ console.error('[CANCEL] bulk status update failed', e.message); }
  } finally {
    browserPromise=null; // force fresh browser next run
  }
}
async function getBrowser(){
  if(!browserPromise){
    browserPromise=puppeteer.launch({ headless:true, ignoreHTTPSErrors:true, args:[ '--no-sandbox','--disable-setuid-sandbox','--disable-dev-shm-usage' ] });
  }
  return browserPromise;
}

// ---------- Real-time streaming (SSE) ----------
const sseClients = new Set();
function broadcastScanUpdate(row){
  if(!row.generation) row.generation = currentScanGeneration;
  const payload = JSON.stringify(row);
  for(const res of sseClients){
    try { res.write(`event:update\ndata:${payload}\n\n`); } catch{ /* ignore broken pipe */ }
  }
}

// Detect overlays & popup windows - Enhanced detection patterns
const MALWARE_WORDS=['virus','malware','infected','security alert','scan now','threat detected','download antivirus','your computer is infected','critical security warning','trojan detected','spyware','adware','ransomware','suspicious activity','immediate action required','click here to clean','security threat','system compromised'];
const GAMBLING_WORDS=['casino','bet','bets','sportsbook','jackpot','roulette','blackjack','poker','slots','slot machine','free spins','win money','betting','gamble','lottery','scratch cards','play now','bonus offer','deposit now'];
const SUSPICIOUS_REDIRECTS=['warning','alert','security','update','flash','java','adobe','microsoft','apple','google','facebook','amazon','paypal','bank'];
const BOT_PROTECTION_WORDS=['captcha','cloudflare','are you human','verify you are human','checking your browser','please wait','loading','ddos protection','security check','human verification'];

// Enhanced anomaly detection function
async function detectAnomalies(page, url) {
  const anomalies = [];
  
  try {
    // Check for excessive redirects
    const currentUrl = page.url();
    if (currentUrl !== url && !currentUrl.startsWith('https://' + url) && !currentUrl.startsWith('http://' + url)) {
      anomalies.push(`Suspicious redirect: ${url} -> ${currentUrl}`);
    }
    
    // Check for popup windows and new tabs
    const pages = await page.browser().pages();
    if (pages.length > 1) {
      anomalies.push('Multiple tabs/popups opened');
    }
    
    // Check for suspicious JavaScript alerts
    let alertDetected = false;
    page.on('dialog', dialog => {
      alertDetected = true;
      const message = dialog.message().toLowerCase();
      if (MALWARE_WORDS.some(word => message.includes(word))) {
        anomalies.push(`Suspicious alert: ${message.substring(0, 100)}`);
      }
      dialog.dismiss();
    });
    
    // Check page content for additional threats
    const pageAnalysis = await page.evaluate(() => {
      const results = {
        hasAutoPlay: false,
        hasDownloadLinks: false,
        hasPhishingForms: false,
        suspiciousIframes: 0,
        externalScripts: 0
      };
      
      // Check for auto-playing media
      const media = document.querySelectorAll('video[autoplay], audio[autoplay]');
      results.hasAutoPlay = media.length > 0;
      
      // Check for suspicious download links
      const downloadLinks = document.querySelectorAll('a[href*=".exe"], a[href*=".zip"], a[href*=".dmg"], a[download]');
      results.hasDownloadLinks = downloadLinks.length > 0;
      
      // Check for phishing-like forms
      const forms = document.querySelectorAll('form');
      forms.forEach(form => {
        const inputs = form.querySelectorAll('input[type="password"], input[type="email"], input[name*="card"], input[name*="ssn"]');
        if (inputs.length > 0) results.hasPhishingForms = true;
      });
      
      // Check for suspicious iframes
      const iframes = document.querySelectorAll('iframe');
      results.suspiciousIframes = iframes.length;
      
      // Count external scripts
      const scripts = document.querySelectorAll('script[src]');
      scripts.forEach(script => {
        if (script.src && !script.src.includes(window.location.hostname)) {
          results.externalScripts++;
        }
      });
      
      return results;
    });
    
    // Add anomalies based on analysis
    if (pageAnalysis.hasAutoPlay) anomalies.push('Auto-playing media detected');
    if (pageAnalysis.hasDownloadLinks) anomalies.push('Suspicious download links detected');
    if (pageAnalysis.hasPhishingForms) anomalies.push('Potential phishing form detected');
    if (pageAnalysis.suspiciousIframes > 5) anomalies.push(`Excessive iframes: ${pageAnalysis.suspiciousIframes}`);
    if (pageAnalysis.externalScripts > 10) anomalies.push(`Many external scripts: ${pageAnalysis.externalScripts}`);
    
    return anomalies;
    
  } catch (error) {
    console.error('[ANOMALY] Detection failed:', error.message);
    return [];
  }
}

// Lightweight HTTP probe (no Puppeteer) for speed
function quickHttpProbe(host, useHttps=true){
  return new Promise(resolve=>{
    const mod= useHttps ? https : require('http');
    const req=mod.request({ method:'GET', host, path:'/', timeout:QUICK_HTTP_TIMEOUT, servername:host, rejectUnauthorized:false, port: useHttps?443:80 }, res=>{
      const code=res.statusCode; res.resume(); req.destroy(); resolve({ status:code, scheme: useHttps? 'https':'http' });
    });
    req.on('error',e=>resolve({ error:e, scheme: useHttps? 'https':'http' }));
    req.on('timeout',()=>{ req.destroy(); resolve({ timeout:true, scheme: useHttps? 'https':'http' }); });
    req.end();
  });
}

async function captureWithPuppeteer(url, id){
  if(cancelRequested){ return { navError: new Error('cancelled'), navTimedOut:false, httpStatus:null, overlayType:null, overlaySnippet:null, screenshotRel:null, additionalAnomalies:null }; }
  // Configurable timeout (default 30s) separate from legacy PUPPETEER_NAV_TIMEOUT
  const navTimeout = parseInt(process.env.PUPPETEER_TIMEOUT || '30000',10);
  const browser = await getBrowser();
  const page = await browser.newPage();
  let popupOpened=false; 
  page.on('popup',()=>{ popupOpened=true; });
  
  await page.setUserAgent(USER_AGENT);
  await page.setViewport({ width:1366, height:900 });
  
  let response=null, navError=null, timedOut=false;
  let requestCount = 0;
  let blockedRequests = [];
  
  // Monitor network requests for suspicious activity
  await page.setRequestInterception(true);
  page.on('request', request => {
    requestCount++;
    const requestUrl = request.url();
    
    // Block known ad/malware domains (basic filtering)
    const suspiciousDomains = ['doubleclick.net', 'googleadservices.com', 'googlesyndication.com'];
    if(suspiciousDomains.some(domain => requestUrl.includes(domain))) {
      blockedRequests.push(requestUrl);
      request.abort();
    } else {
      request.continue();
    }
  });
  
  try {
    // Faster: load DOM first, then attempt a short network idle wait (non-blocking if busy site)
  if(cancelRequested){ try { await page.close(); } catch{} return { navError:new Error('cancelled'), httpStatus:null }; }
    response = await page.goto(url, { waitUntil:'domcontentloaded', timeout: navTimeout });
  if(cancelRequested){ try { await page.close(); } catch{} return { navError:new Error('cancelled'), httpStatus: response?response.status():null };
  }
    try { await page.waitForNetworkIdle({ idleTime:600, timeout:2000 }); } catch{}
    await page.waitForTimeout(500); // Increased wait for better content detection
  } catch(e){
    navError=e;
    if((e.message||'').toLowerCase().includes('timeout')){
      timedOut=true;
      // Fallback: try a softer wait to grab whatever rendered so far
      try { await page.waitForSelector('body',{ timeout:3000 }); } catch{}
    }
  }
  
  let overlayType=null, overlaySnippet=null, additionalAnomalies=[];
  
  if(!navError || timedOut){
    try {
      // Enhanced overlay detection
      const overlay = await page.evaluate((malwareWords, gamblingWords, botWords) => {
        const vw=window.innerWidth, vh=window.innerHeight;
        const results = {
          overlayText: '',
          hasFixedElements: false,
          hasHighZIndex: false,
          suspiciousPopups: 0
        };
        
        // Check for overlay elements
        const big=[...document.querySelectorAll('div,section,aside,modal,.popup,.overlay')].filter(el=>{
          const st=getComputedStyle(el);
          if(st.display==='none'||st.visibility==='hidden'||st.opacity==='0') return false;
          const r=el.getBoundingClientRect();
          const covers=r.width>=vw*0.45 && r.height>=vh*0.45;
          const z=parseInt(st.zIndex)||0;
          
          // Check for high z-index elements
          if(z >= 1000) results.hasHighZIndex = true;
          
          // Check for fixed position elements
          if(st.position === 'fixed') results.hasFixedElements = true;
          
          return covers && z>=900;
        }).slice(0,3).map(el=>el.innerText.slice(0,300));
        
        results.overlayText = big.join('\n');
        
        // Count elements that look like popups
        const popupSelectors = ['.popup', '.modal', '.dialog', '[id*="popup"]', '[class*="popup"]'];
        popupSelectors.forEach(selector => {
          results.suspiciousPopups += document.querySelectorAll(selector).length;
        });
        
        return results;
      }, MALWARE_WORDS, GAMBLING_WORDS, BOT_PROTECTION_WORDS);
      
      const txt=(overlay.overlayText||'').toLowerCase();
      if(txt){
        if(MALWARE_WORDS.some(w=>txt.includes(w))) { 
          overlayType=STATUS.MALWARE_OVERLAY; 
          overlaySnippet=txt.slice(0,160); 
        }
        else if(GAMBLING_WORDS.some(w=>txt.includes(w))) { 
          overlayType=STATUS.GAMBLING_OVERLAY; 
          overlaySnippet=txt.slice(0,160); 
        }
        else if(BOT_PROTECTION_WORDS.some(w=>txt.includes(w))) { 
          overlayType=STATUS.BOT_PROTECTION_BLOCKED; 
          overlaySnippet=txt.slice(0,160); 
        }
      }
      
      if(popupOpened && !overlayType){ 
        overlayType=STATUS.MALWARE_OVERLAY; 
        overlaySnippet='popup window opened'; 
      }
      
      // Additional checks
      if(overlay.suspiciousPopups > 0) {
        additionalAnomalies.push(`${overlay.suspiciousPopups} suspicious popup elements`);
      }
      
      if(requestCount > 50) {
        additionalAnomalies.push(`excessive requests: ${requestCount}`);
      }
      
      if(blockedRequests.length > 0) {
        additionalAnomalies.push(`blocked ${blockedRequests.length} suspicious requests`);
      }
      
      // Run additional anomaly detection
      const detectedAnomalies = await detectAnomalies(page, url);
      additionalAnomalies.push(...detectedAnomalies);
      
    } catch(e) {
      console.error('[OVERLAY] Detection failed:', e.message);
    }
  }
  
  let screenshotRel=null;
  // Attempt screenshot on success OR soft-timeout if any DOM present (even with overlay)
  if(response || timedOut){
    try { 
      const html=await page.content(); 
      if(html && html.length>30){ 
        screenshotRel = await takeScreenshot(page, id, url); 
      } 
    } catch(e) {
      console.error('[SCREENSHOT] Failed:', e.message);
    }
  }
  
  try { await page.close(); } catch{}
  
  return { 
    navError, 
    navTimedOut: timedOut, 
    httpStatus: response?response.status():null, 
    overlayType, 
    overlaySnippet, 
    screenshotRel,
    additionalAnomalies: additionalAnomalies.length > 0 ? additionalAnomalies.join('; ') : null
  };
}

async function takeScreenshot(page, siteId, url){
  try {
    // URL-based naming: google.com -> google
    const cleanUrl = url.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
    const filename = `${cleanUrl}.png`;
    
    // Take screenshot to buffer instead of file
    const screenshotBuffer = await page.screenshot({ 
      fullPage: true, 
      type: 'png' 
    });
    
    // Upload to Cloudinary
    const uploadResult = await new Promise((resolve, reject) => {
      cloudinary.uploader.upload_stream(
        {
          resource_type: 'image',
          public_id: `screenshots/${cleanUrl}`, // Organize in screenshots folder
          folder: 'website-monitor',
          overwrite: true, // Replace existing screenshots
          format: 'png'
        },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      ).end(screenshotBuffer);
    });
    
    console.log(`[SHOT] Screenshot uploaded to Cloudinary: ${filename}`);
    return uploadResult.secure_url; // Return Cloudinary URL
    
  } catch(e){ 
    console.error('[SHOT] failed', siteId, url, e.message); 
    return null; 
  }
}

// DB row variant
async function checkDbRow(row, opts={ clientView:false }){
  if(cancelRequested){
    // Persist cancelled state quickly without heavy work
    await safeUpdateUrl(row, { status: STATUS.CANCELLED, last_checked_at:new Date().toISOString() });
    broadcastScanUpdate({ id: row.id, url: row.url, status: STATUS.CANCELLED, last_checked_at:new Date().toISOString(), screenshot_url:null });
    return { status: STATUS.CANCELLED, last_checked_at:new Date().toISOString(), id: row.id };
  }
  const host=row.url.split('/')[0];
  const reasons=[]; let primary=STATUS.OK; let ssl_expires_at=null;
  try { await dns.lookup(host); } catch { primary=STATUS.DNS_ERROR; reasons.push('DNS issue'); return await persist(primary,reasons.join('; ')); }
  const sslInfo=await analyzeSSL(host);
  if(sslInfo.expires) ssl_expires_at=sslInfo.expires;
  if(sslInfo.status!=='OK'){
    const mapped=STATUS[sslInfo.status]||sslInfo.status;
    primary=mapped;
    if(mapped===STATUS.SSL_EXPIRED) reasons.push('SSL expired');
    else if(mapped===STATUS.SSL_UNTRUSTED) reasons.push('SSL not certified');
    else if(mapped===STATUS.SSL_MISMATCH) reasons.push('SSL invalid (hostname mismatch)');
    else if(mapped===STATUS.SSL_ERROR) reasons.push(`SSL error: ${sslInfo.detail||'unknown'}`);
  else if(mapped===STATUS.SSL_MISSING) reasons.push('SSL missing');
    else if(mapped===STATUS.SSL_EXPIRING_SOON) reasons.push('SSL about to expire (<7 days)');
  } else if(sslInfo.expires){
    const days=(new Date(sslInfo.expires).getTime()-Date.now())/86400000;
    if(days<7){ reasons.push('SSL about to expire (<7 days)'); if(primary===STATUS.OK) primary=STATUS.SSL_EXPIRING_SOON; }
  }
  // Reachability probe (non-fatal) just to pick initial scheme; never early-return so Puppeteer always tries.
  let httpStatus=null; let navError=null; let overlayType=null; let overlaySnippet=null; let screenshot_url=null; let scheme='https';
  let probeTimedOut=false; let probeConnError=false;
  const probeHttps=await quickHttpProbe(row.url, true);
  if(probeHttps.timeout){
    const probeHttp=await quickHttpProbe(row.url,false);
    if(probeHttp.timeout){ probeTimedOut=true; scheme='https'; }
    else if(probeHttp.error){ probeConnError=true; scheme='http'; }
    else { scheme='http'; httpStatus=probeHttp.status; }
  } else if(probeHttps.error){
    const probeHttp=await quickHttpProbe(row.url,false);
    if(probeHttp.timeout){ probeTimedOut=true; scheme='http'; }
    else if(probeHttp.error){ probeConnError=true; scheme='http'; }
    else { scheme='http'; httpStatus=probeHttp.status; }
  } else { httpStatus=probeHttps.status; scheme='https'; }
  const full=await captureWithPuppeteer(`${scheme}://${row.url}`, row.id).catch(()=>null);
  if(full){
    httpStatus=full.httpStatus; navError=full.navError; overlayType=full.overlayType; overlaySnippet=full.overlaySnippet;
   if(full.screenshotRel){ screenshot_url = full.screenshotRel; }
    if(navError){
      const msg=(navError.message||'').toLowerCase();
      const isTimeout=/timeout|timed out|navigation timeout/.test(msg);
      // If we timed out but still captured screenshot treat as slow OK (unless previous error already)
      if(isTimeout && full.screenshotRel){
        if(primary===STATUS.OK) reasons.push('Slow load (networkidle timeout)');
      } else if(/econnrefused|connrefused/.test(msg)){
        primary=STATUS.CONNECTION_REFUSED; reasons.push('Connection refused');
      } else if(isTimeout){
        primary=STATUS.TIMEOUT; reasons.push('Timeout');
      } else {
        primary=STATUS.HTTP_ERROR; reasons.push('Navigation failure');
      }
    } else if(typeof httpStatus==='number'){
      if(httpStatus>=400) { primary=`HTTP_${httpStatus}`; reasons.push(`HTTP ${httpStatus}`); }
      else if(httpStatus>=300) { if(primary===STATUS.OK) reasons.push(`Redirect (${httpStatus})`); }
      else if(httpStatus>=200) { if(primary===STATUS.OK) reasons.push('OK'); }
    }
    if(overlayType){ primary=overlayType; if(overlayType===STATUS.MALWARE_OVERLAY) reasons.push('Malware popup detected'); else if(overlayType===STATUS.GAMBLING_OVERLAY) reasons.push('Gambling popup detected'); else if(overlayType===STATUS.BOT_PROTECTION_BLOCKED) reasons.push('Bot protection / challenge'); }
    // If HTTPS navigation & screenshot succeeded, override a prior false SSL_MISSING classification
    if(full.screenshotRel && scheme==='https' && primary===STATUS.SSL_MISSING){
      const idx=reasons.findIndex(r=>/ssl missing/i.test(r));
      if(idx>=0) reasons.splice(idx,1);
      primary=STATUS.OK;
      if(!reasons.length) reasons.push('OK');
    }
  } else {
    // Puppeteer failed to launch entirely; fallback classify from probe results
    if(probeConnError){ primary=STATUS.CONNECTION_REFUSED; reasons.push('Connection refused'); }
    else if(probeTimedOut){ primary=STATUS.TIMEOUT; reasons.push('Timeout'); }
  }
  return await persist(primary, reasons.length?reasons.join('; '):'OK', ssl_expires_at, null, screenshot_url);

  async function persist(st, err, sslExp, loadCtx, screenshot_url){
    try { if(loadCtx && loadCtx.page) await loadCtx.page.close(); } catch{}
  // Do NOT include error_details in DB payload (column not present). Only return it to client.
  const payload={ status:st, last_checked_at:new Date().toISOString(), screenshot_url: screenshot_url||null, ssl_expires_at: sslExp };
  await safeUpdateUrl(row, payload);
  broadcastScanUpdate({ id: row.id, url: row.url, ...payload });
    if(st===STATUS.OK) console.log(`[SCAN] ${row.url} OK`);
    else if(st===STATUS.SSL_EXPIRED) console.log(`[ALERT] ${row.url} SSL expired`);
    else if(st===STATUS.SSL_EXPIRING_SOON) console.log(`[ALERT] ${row.url} SSL expiring soon`);
    else if(st===STATUS.SSL_UNTRUSTED) console.log(`[ALERT] ${row.url} SSL untrusted`);
    else if(st===STATUS.SSL_MISMATCH) console.log(`[ALERT] ${row.url} SSL mismatch`);
    else if(st===STATUS.TIMEOUT) console.log(`[ALERT] ${row.url} Timeout`);
    else if(st===STATUS.CONNECTION_REFUSED) console.log(`[ALERT] ${row.url} Connection refused`);
    else if(st===STATUS.DNS_ERROR) console.log(`[ALERT] ${row.url} DNS error`);
    else if(st===STATUS.HTTP_ERROR || /^HTTP_\d+/.test(st)) console.log(`[ALERT] ${row.url} ${st}`);
    else if(st===STATUS.MALWARE_OVERLAY) console.log(`[ALERT] ${row.url} Malware overlay`);
    else if(st===STATUS.GAMBLING_OVERLAY) console.log(`[ALERT] ${row.url} Gambling overlay`);
    else if(st===STATUS.BOT_PROTECTION_BLOCKED) console.log(`[ALERT] ${row.url} Bot protection blocked`);
    else if(st===STATUS.ANOMALY_SUSPECTED) console.log(`[ALERT] ${row.url} Anomaly suspected`);
    if(opts.clientView){
      return {
        id: row.id,
        url: row.url,
        status: st===STATUS.OK ? 'ok' : 'error',
        original_status: st,
        screenshot: payload.screenshot_url,
        error_details: err || (st===STATUS.OK ? 'OK' : st),
        ssl_expires_at: sslExp || null,
        last_checked_at: payload.last_checked_at
      };
    }
    return { ...payload, id: row.id };
  }
}

// Safe update helper (drops unknown columns gracefully)
async function safeUpdateUrl(row, payload){
  const { id, url } = row;
  if(!safeUpdateUrl._missing) safeUpdateUrl._missing=new Set();
  const missing=safeUpdateUrl._missing;

  // Remove any previously detected missing columns from payload proactively
  for(const col of [...missing]){ if(col in payload) delete payload[col]; }

  let attemptPayload={ ...payload };
  while(true){
  const { error } = await supabase.from('urls').update(attemptPayload).eq('id', id);
    if(!error) return true;
    const msg=error.message||'';
    console.error('[DB] update failed', url, msg);
    const m=msg.match(/Could not find the '([^']+)' column/);
    if(!m){
      return false; // unhandled error
    }
    const col=m[1];
    missing.add(col);
    delete attemptPayload[col];
    // Ensure we always keep at least status + last_checked_at so table can reflect progress
    const keys=Object.keys(attemptPayload);
    if(!keys.includes('status') || !keys.includes('last_checked_at')){
      attemptPayload.status=attemptPayload.status || payload.status;
      attemptPayload.last_checked_at=attemptPayload.last_checked_at || payload.last_checked_at;
    }
    // Retry loop with reduced payload
    if(Object.keys(attemptPayload).length===2 && !('status' in attemptPayload && 'last_checked_at' in attemptPayload)){
      // nothing else meaningful to try
      return false;
    }
  }
}

function logStatus(site){
  if(site.status===STATUS.OK) console.log(`[SCAN] ${site.url} OK`);
  else if(site.status===STATUS.SSL_EXPIRED) console.log(`[ALERT] ${site.url} SSL expired`);
  else if(site.status===STATUS.SSL_EXPIRING_SOON) console.log(`[ALERT] ${site.url} SSL expiring soon (${site.error||''})`);
  else if(site.status===STATUS.SSL_UNTRUSTED) console.log(`[ALERT] ${site.url} SSL untrusted`);
  else if(site.status===STATUS.SSL_MISMATCH) console.log(`[ALERT] ${site.url} SSL mismatch`);
  else if(site.status===STATUS.TIMEOUT) console.log(`[ALERT] ${site.url} Timeout`);
  else if(site.status===STATUS.CONNECTION_REFUSED) console.log(`[ALERT] ${site.url} Connection refused`);
  else if(site.status===STATUS.DNS_ERROR) console.log(`[ALERT] ${site.url} DNS error`);
  else if(site.status===STATUS.HTTP_ERROR) console.log(`[ALERT] ${site.url} ${site.error}`);
  else if(site.status===STATUS.MALWARE_OVERLAY) console.log(`[ALERT] ${site.url} Malware overlay`);
  else if(site.status===STATUS.GAMBLING_OVERLAY) console.log(`[ALERT] ${site.url} Gambling overlay`);
  else if(site.status===STATUS.BOT_PROTECTION_BLOCKED) console.log(`[ALERT] ${site.url} Bot protection blocked`);
  else if(site.status===STATUS.ANOMALY_SUSPECTED) console.log(`[ALERT] ${site.url} Anomaly suspected`);
}

// ---------------- Screenshot Cleanup Utility ----------------
async function cleanupOldScreenshots(){
  try {
    const files = await fs.readdir(SCREENSHOT_DIR);
    let cleanedCount = 0;
    
    // Clean up ALL legacy naming formats (site-{id}.png, site-{id}-{timestamp}.png)
    for(const file of files) {
      if(!file.endsWith('.png')) continue;
      
      // Match legacy formats: site-{id}.png OR site-{id}-{timestamp}.png
      const legacyMatch = file.match(/^site-(\d+)(-\d{13})?\.png$/);
      if(legacyMatch) {
        const filePath = path.join(SCREENSHOT_DIR, file);
        try {
          await fs.unlink(filePath);
          cleanedCount++;
          console.log(`[CLEANUP] Removed legacy screenshot: ${file}`);
        } catch(e) {
          console.warn(`[CLEANUP] Failed to delete ${file}:`, e.message);
        }
      }
    }
    
    // Clean up any very old files (30+ days) as failsafe
    const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
    for(const file of files) {
      if(!file.endsWith('.png')) continue;
      
      const filePath = path.join(SCREENSHOT_DIR, file);
      try {
        const stats = await fs.stat(filePath);
        if(stats.mtime.getTime() < thirtyDaysAgo) {
          // Only delete if it looks like an old format (has numbers/dashes)
          if(/\d/.test(file) && file.includes('-')) {
            await fs.unlink(filePath);
            cleanedCount++;
            console.log(`[CLEANUP] Removed very old file: ${file}`);
          }
        }
      } catch {} // Ignore errors for individual files
    }
    
    if(cleanedCount > 0) {
      console.log(`[CLEANUP] Cleaned up ${cleanedCount} legacy screenshots`);
    }
    
    return cleanedCount;
  } catch(e) {
    console.error('[CLEANUP] Screenshot cleanup failed:', e.message);
    return 0;
  }
}

// Schedule cleanup every hour during transition, then every 6 hours  
try {
  cron.schedule('0 * * * *', () => {
    console.log('[CLEANUP] Running screenshot cleanup...');
    cleanupOldScreenshots().catch(e => console.error('[CLEANUP] Error:', e.message));
  }, { timezone: process.env.SCAN_TZ||'UTC' });
  console.log('[CRON] Screenshot cleanup scheduled every hour (transition period)');
} catch(e) {
  console.error('[CRON] Cleanup schedule failed:', e.message);
}
async function runScan(){
  if(cancelRequested){
    console.log('[SCAN] Cancellation flag set before start; aborting run');
    return;
  }
  currentScanGeneration++;
  const { data: list } = await supabase.from('urls').select('*');
  if(!list || !list.length) return;
  let index=0;
  async function worker(){
    while(index<list.length && !cancelRequested){
      const row=list[index++];
      const prev=lastStatusMap.get(row.id);
      const result=await checkDbRow(row);
      const cur=result.status;
      // Alert logic:
      // 1. Initial detection: no prev & current is error => send
      // 2. Transition into error from OK/non-error => send
      // 3. Transition out of error => recovery email
      if(!prev && isErrorStatus(cur)){
        await sendAlertEmail(row, result);
      } else if(prev && prev!==cur) {
        if(!isErrorStatus(prev) && isErrorStatus(cur)){
          await sendAlertEmail(row, result);
        } else if(isErrorStatus(prev) && !isErrorStatus(cur)){
          console.log(`[RECOVERY] ${row.url} back online`);
          await sendRecoveryEmail(row, prev);
        }
      }
      lastStatusMap.set(row.id, cur);
    }
  }
  await Promise.all(Array.from({length:Math.min(SCAN_CONCURRENCY,list.length)},()=>worker()));
  if(cancelRequested){
    console.log('[SCAN] Run ended early due to cancellation');
  }
}

// Cron-based scanning (default hourly) - override with SCAN_CRON env
const SCAN_CRON = EFFECTIVE_SCAN_CRON;
try {
  cron.schedule(SCAN_CRON, ()=> {
    const ts=new Date();
    const timeStr=ts.toLocaleTimeString('en-US',{ hour:'2-digit', minute:'2-digit', hour12:true });
    console.log(`[CRON] Tick ${timeStr} (paused=${scanningPaused} cancelled=${cancelRequested})`);
    if(cancelRequested){ console.log('[CRON] Skip: cancellation active'); return; }
    if(scanningPaused){ console.log('[CRON] Skip: scanning paused'); return; }
    runScan().catch(e=>console.error('[SCAN] cycle error', e.message));
  }, { timezone: process.env.SCAN_TZ||'UTC' });
  console.log(`[CRON] scan scheduled ${SCAN_CRON}`);
  setTimeout(()=>{ if(!scanningPaused && !cancelRequested) runScan().catch(e=>console.error('[SCAN] initial error', e.message)); }, 5000);
} catch(e){ console.error('[CRON] scan schedule failed', e.message); }

async function sendDailySummary(){
  if(!mailer) return;
  const { data: rows } = await supabase.from('urls').select('*');
  if(!rows) return;
  
  const total = rows.length;
  const ok = rows.filter(r => r.status === STATUS.OK).length;
  const errors = total - ok;
  
  // Categorize issues
  const issues = {
    ssl_expired: rows.filter(r => r.status === STATUS.SSL_EXPIRED).length,
    ssl_expiring: rows.filter(r => r.status === STATUS.SSL_EXPIRING_SOON).length,
    ssl_issues: rows.filter(r => r.status?.includes('SSL_')).length,
    malware: rows.filter(r => r.status === STATUS.MALWARE_OVERLAY).length,
    gambling: rows.filter(r => r.status === STATUS.GAMBLING_OVERLAY).length,
    timeouts: rows.filter(r => r.status === STATUS.TIMEOUT).length,
    http_errors: rows.filter(r => r.status?.includes('HTTP_')).length,
    dns_errors: rows.filter(r => r.status === STATUS.DNS_ERROR).length
  };
  
  const dashboardUrl = `${BASE_PUBLIC_URL}/dashboard`;
  
  // Create summary sections
  let summaryHtml = `
    <div style="font-family: Arial, sans-serif; max-width: 800px;">
      <h2>📊 Daily Website Monitoring Summary</h2>
      <p><strong>Report Date:</strong> ${new Date().toLocaleDateString()}</p>
      
      <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3>Overall Status</h3>
        <div style="display: flex; gap: 20px; flex-wrap: wrap;">
          <div style="background: ${ok === total ? '#d4edda' : '#fff3cd'}; padding: 15px; border-radius: 5px; flex: 1; min-width: 120px;">
            <div style="font-size: 24px; font-weight: bold; color: ${ok === total ? '#155724' : '#856404'};">${ok}</div>
            <div>✅ Healthy Sites</div>
          </div>
          <div style="background: ${errors > 0 ? '#f8d7da' : '#d4edda'}; padding: 15px; border-radius: 5px; flex: 1; min-width: 120px;">
            <div style="font-size: 24px; font-weight: bold; color: ${errors > 0 ? '#721c24' : '#155724'};">${errors}</div>
            <div>❌ Issues Detected</div>
          </div>
          <div style="background: #e9ecef; padding: 15px; border-radius: 5px; flex: 1; min-width: 120px;">
            <div style="font-size: 24px; font-weight: bold; color: #495057;">${total}</div>
            <div>📈 Total Monitored</div>
          </div>
        </div>
      </div>
  `;
  
  // Issue breakdown
  if(errors > 0) {
    summaryHtml += `
      <div style="background: #fff; padding: 20px; border: 1px solid #dee2e6; border-radius: 8px; margin: 20px 0;">
        <h3>🚨 Issue Breakdown</h3>
        <ul style="list-style: none; padding: 0;">
    `;
    
    if(issues.ssl_expired > 0) summaryHtml += `<li style="padding: 5px 0;">🔒❌ SSL Expired: ${issues.ssl_expired}</li>`;
    if(issues.ssl_expiring > 0) summaryHtml += `<li style="padding: 5px 0;">🔒⚠️ SSL Expiring Soon: ${issues.ssl_expiring}</li>`;
    if(issues.malware > 0) summaryHtml += `<li style="padding: 5px 0;">🦠 Malware Detected: ${issues.malware}</li>`;
    if(issues.gambling > 0) summaryHtml += `<li style="padding: 5px 0;">🎰 Gambling Content: ${issues.gambling}</li>`;
    if(issues.timeouts > 0) summaryHtml += `<li style="padding: 5px 0;">⏰ Timeouts: ${issues.timeouts}</li>`;
    if(issues.http_errors > 0) summaryHtml += `<li style="padding: 5px 0;">🔗❌ HTTP Errors: ${issues.http_errors}</li>`;
    if(issues.dns_errors > 0) summaryHtml += `<li style="padding: 5px 0;">🌐❌ DNS Errors: ${issues.dns_errors}</li>`;
    
    summaryHtml += `</ul></div>`;
  }
  
  // Sites table
  const statusEmoji = {
    'OK': '✅',
    'SSL_EXPIRED': '🔒❌',
    'SSL_EXPIRING_SOON': '🔒⚠️',
    'SSL_UNTRUSTED': '🔒⚠️',
    'SSL_MISMATCH': '🔒⚠️',
    'MALWARE_OVERLAY': '🦠',
    'GAMBLING_OVERLAY': '🎰',
    'TIMEOUT': '⏰',
    'CONNECTION_REFUSED': '🚫',
    'DNS_ERROR': '🌐❌'
  };
  
  const tableRows = rows.map(r => {
    const emoji = statusEmoji[r.status] || '❌';
    const statusColor = r.status === 'OK' ? '#28a745' : '#dc3545';
    return `
      <tr style="border-bottom: 1px solid #dee2e6;">
        <td style="padding: 8px;">${r.url}</td>
        <td style="padding: 8px; color: ${statusColor};">${emoji} ${r.status}</td>
        <td style="padding: 8px; font-size: 12px;">${r.error_details || ''}</td>
        <td style="padding: 8px; font-size: 12px;">${r.ssl_expires_at ? new Date(r.ssl_expires_at).toLocaleDateString() : ''}</td>
      </tr>
    `;
  }).join('');
  
  summaryHtml += `
    <div style="margin: 20px 0;">
      <h3>📋 Detailed Status</h3>
      <table style="width: 100%; border-collapse: collapse; background: white; border: 1px solid #dee2e6;">
        <thead>
          <tr style="background: #f8f9fa;">
            <th style="padding: 12px; text-align: left; border-bottom: 2px solid #dee2e6;">URL</th>
            <th style="padding: 12px; text-align: left; border-bottom: 2px solid #dee2e6;">Status</th>
            <th style="padding: 12px; text-align: left; border-bottom: 2px solid #dee2e6;">Details</th>
            <th style="padding: 12px; text-align: left; border-bottom: 2px solid #dee2e6;">SSL Expires</th>
          </tr>
        </thead>
        <tbody>
          ${tableRows}
        </tbody>
      </table>
    </div>
    
    <div style="margin: 20px 0; padding: 15px; background: #e9ecef; border-radius: 5px;">
      <p><strong>🔗 Dashboard:</strong> <a href="${dashboardUrl}" target="_blank">Access Full Dashboard</a></p>
      <p style="font-size: 12px; color: #666; margin: 10px 0 0 0;">
  This summary is sent daily at 9 AM. Issues are monitored ${SCAN_FREQUENCY_DESC} with immediate alerts.
      </p>
    </div>
  </div>
  `;
  
  const subject = `📊 Daily Report: ${ok}/${total} Sites OK ${errors > 0 ? `| ${errors} Issues` : ''}`;
  await sendMail(subject, summaryHtml);
  console.log(`[DAILY] Enhanced summary email sent - ${ok}/${total} sites OK, ${errors} issues`);
}

try { cron.schedule(DAILY_CRON, ()=>sendDailySummary().catch(e=>console.error('[DAILY] error', e.message)), { timezone: process.env.SCAN_TZ||'UTC' }); console.log(`[CRON] daily summary scheduled ${DAILY_CRON}`); } catch(e){ console.error('[CRON] schedule failed', e.message); }

// ---------------- Express API + Auth (unchanged auth routes) ----------------
const app = express();
app.use(cors({ origin:'https://frontend-nttk.onrender.com', credentials:true }));
app.use(express.json());
app.use(session({ secret: SESSION_SECRET, resave:false, saveUninitialized:false, cookie:{ httpOnly:true, sameSite:'lax' }}));
// Serve new photos path + keep backwards compatibility for previously generated /screenshots files if any
app.use('/photos', express.static(SCREENSHOT_DIR));
app.use('/screenshots', express.static(SCREENSHOT_DIR));
const upload = multer({ storage: multer.memoryStorage() });

function auth(req,res,next){ if(req.session && req.session.adminEmail) return next(); return res.status(401).json({ message:'Not authenticated' }); }

// Auth routes (kept exactly as original requirement)
app.post('/api/admin/signup', async (req,res)=>{ const { email,password }=req.body; if(!email||!password) return res.status(400).json({message:'Email and password required'}); try { const hash=await bcrypt.hash(password,10); const { error } = await supabase.from('admin').insert({ email, password_hash:hash }); if (error) { if((error.message||'').toLowerCase().includes('duplicate')) return res.status(409).json({ message:'Email already registered'}); throw error; } req.session.adminEmail=email; res.json({ email }); } catch(e){ res.status(500).json({ message:'Signup failed', error:e.message }); } });
app.post('/api/admin/login', async (req,res)=>{ const { email,password }=req.body; if(!email||!password) return res.status(400).json({message:'Email and password required'}); try { const { data: row } = await supabase.from('admin').select('*').eq('email',email).single(); if(!row) return res.status(401).json({ message:'Invalid credentials'}); const ok=await bcrypt.compare(password,row.password_hash); if(!ok) return res.status(401).json({ message:'Invalid credentials'}); req.session.adminEmail=email; res.json({ email }); } catch(e){ res.status(500).json({ message:'Login failed', error:e.message }); } });
app.post('/api/admin/logout',(req,res)=>{ if(req.session) req.session.destroy(()=>{}); res.json({ message:'Logged out'}); });
app.get('/api/admin/me',(req,res)=>{ if(req.session&&req.session.adminEmail) return res.json({ email:req.session.adminEmail }); return res.status(401).json({ message:'Not authenticated'}); });
app.post('/api/admin/test-email', auth, async (req,res)=>{ try { const ok=await sendMail('Test Monitoring Email', `<p>Test at ${new Date().toISOString()}</p>`); if(!ok) return res.status(500).json({ message:'Test email failed'}); res.json({ message:'Test email dispatched'});} catch(e){ res.status(500).json({ message:'Test email failed', error:e.message }); } });

// ---------------- URL submission & CSV import (modernized) ----------------
const urlsAuth = ALLOW_PUBLIC_SUBMISSION ? (req,res,next)=>next() : auth;
app.get('/api/urls', urlsAuth, async (req,res)=>{
  try {
    const { data, error } = await supabase.from('urls').select('*').order('created_at', { ascending:false });
    if(error) throw error;
    const normalized=(data||[]).map(r=>{
      if(r.error_details===undefined && r.error!==undefined) r.error_details=r.error;
      if(r.screenshot_url===undefined && r.screenshot) r.screenshot_url=r.screenshot;
      if(r.last_checked_at===undefined && r.lastCheckedAt) r.last_checked_at=r.lastCheckedAt;
      return r;
    });
    res.json(normalized);
  } catch(err){ res.status(500).json({ message:'Failed to fetch urls', error: err.message }); }
});

// (Removed legacy /api/submit & /api/run-checks; single add + bulk import now perform immediate processing.)
// ---- New: explicit single URL add (POST /api/urls) using advanced checker for immediate processing ----
async function processNewRow(row){ try { await checkDbRow(row); } catch(e){ console.error('[NEW-URL] processing failed', row.url, e.message); } }
app.post('/api/urls', urlsAuth, async (req,res)=>{
  try {
    let { url } = req.body || {};
    if(!url) return res.status(400).json({ message:'URL required'});
    url=url.trim().replace(/^https?:\/\//,'').replace(/\/$/,'').toLowerCase();
    if(!url) return res.status(400).json({ message:'Invalid URL'});
    let { data, error } = await supabase.from('urls').insert({ url, status:'Processing' }).select();
    let insertedRow = data && data[0];
    if(error){
      if(/duplicate|unique/i.test(error.message||'')){
        const { data: existing } = await supabase.from('urls').select('*').eq('url',url).single();
        if(existing) insertedRow=existing; else return res.status(409).json({ message:'URL already exists'});
      } else return res.status(500).json({ message:'Insert failed', error:error.message });
    }
    if(!insertedRow) return res.status(500).json({ message:'Insert retrieval failed'});
  const processed = await checkDbRow(insertedRow, { clientView:true });
  res.status(201).json(processed);
  } catch(e){ res.status(500).json({ message:'Add URL failed', error:e.message }); }
});

// ---- New: CSV bulk import (POST /api/import-bulk) ----
app.post('/api/import-bulk', urlsAuth, upload.single('file'), async (req,res)=>{
  try {
    if(!req.file) return res.status(400).json({ message:'CSV file required'});
    const rows=[];
    await new Promise((resolve,reject)=>{
      const stream=Readable.from(req.file.buffer.toString());
      stream.pipe(csv({ headers:false }))
        .on('data',r=>{ const v=(r[0]||Object.values(r)[0]||'').trim(); if(v) rows.push(v); })
        .on('end',resolve).on('error',reject);
    });
    const urls=[...new Set(rows.map(u=>u.replace(/^https?:\/\//,'').replace(/\/$/,'').toLowerCase()).filter(Boolean))];
    if(!urls.length) return res.status(400).json({ message:'No valid URLs in file'});
    const records=urls.map(u=>({ url:u, status:'Processing' }));
    let added=[]; let failed=null;
    try {
      const { data, error } = await supabase.from('urls').insert(records).select();
      if(error) throw error; added=data||[];
    } catch(e){
      // Fallback: insert individually ignoring duplicates
      added=[]; failed=e.message;
      for(const rec of records){
        try {
          const { data, error } = await supabase.from('urls').insert(rec).select();
          if(error){ if(/duplicate|unique/i.test(error.message||'')) { const { data: existing } = await supabase.from('urls').select('*').eq('url',rec.url).single(); if(existing) added.push(existing); } else console.error('[IMPORT] insert error', rec.url, error.message); }
          else if(data && data[0]) added.push(data[0]);
        } catch(inner){ console.error('[IMPORT] row error', rec.url, inner.message); }
      }
    }
  // Process sequentially for immediate statuses
  const processed=[];
  for(const r of added){ const p=await checkDbRow(r, { clientView:true }); processed.push(p); }
  res.status(201).json({ added: processed.length, items: processed, fallback: !!failed });
  } catch(e){ res.status(500).json({ message:'Import failed', error:e.message }); }
});
app.post('/api/run-all', auth, async (req,res)=>{ try { cancelRequested=false; scanningPaused=false; const { data } = await supabase.from('urls').select('*'); await Promise.all((data||[]).map(r=>supabase.from('urls').update({ status:'processing' }).eq('id',r.id))); await runScan(); const { data: fresh } = await supabase.from('urls').select('*').order('created_at',{ascending:false}); res.json({ message:'Full scan complete', items: fresh||[] }); } catch(e){ res.status(500).json({ message:'Full run failed', error:e.message }); }});
// Cancel current run (coarse). Does not delete data.
app.post('/api/cancel-all', auth, async (req,res)=>{
  try {
    if(cancelRequested){
      return res.json({ message:'Cancellation already in progress' });
    }
    await requestCancelAll();
    res.json({ message:'Cancellation requested' });
  } catch(e){
    res.status(500).json({ message:'Cancel failed', error:e.message });
  }
});
// Alias simple cancel endpoint (no delete, idempotent)
app.post('/api/cancel', auth, async (req,res)=>{
  try {
    if(cancelRequested) return res.json({ message:'Already cancelling' });
    await requestCancelAll();
    res.json({ message:'Cancellation requested' });
  } catch(e){ res.status(500).json({ message:'Cancel failed', error:e.message }); }
});
// Helper to bulk delete all URL rows & screenshots
// Helper function to delete screenshot from Cloudinary
async function deleteCloudinaryScreenshot(url) {
  try {
    if (!url || !url.includes('cloudinary.com')) {
      return false; // Not a Cloudinary URL, skip
    }
    
    // Extract public_id from Cloudinary URL
    // URL format: https://res.cloudinary.com/[cloud_name]/image/upload/[version]/[public_id].format
    const urlParts = url.split('/');
    const uploadIndex = urlParts.indexOf('upload');
    if (uploadIndex === -1) return false;
    
    // Get the public_id (remove file extension)
    const publicIdWithExtension = urlParts.slice(uploadIndex + 2).join('/');
    const publicId = publicIdWithExtension.replace(/\.[^/.]+$/, ''); // Remove extension
    
    await cloudinary.uploader.destroy(publicId);
    console.log(`[CLEANUP] Deleted Cloudinary screenshot: ${publicId}`);
    return true;
  } catch (error) {
    console.error('[CLEANUP] Failed to delete Cloudinary screenshot:', error.message);
    return false;
  }
}

async function bulkDeleteAll(){
  // First get all URLs to extract screenshot URLs for Cloudinary cleanup
  const { data: urlRecords, error: fetchError } = await supabase
    .from('urls')
    .select('screenshot_url')
    .neq('id', 0);
  
  // Delete screenshots from Cloudinary
  let removed = 0;
  if (urlRecords && !fetchError) {
    for (const record of urlRecords) {
      if (record.screenshot_url) {
        const deleted = await deleteCloudinaryScreenshot(record.screenshot_url);
        if (deleted) removed++;
      }
    }
  }
  
  // Delete DB rows (neq('id',0) to target all rows; Supabase requires a filter)
  const { error } = await supabase.from('urls').delete().neq('id', 0);
  if (error) throw error;
  
  // Clear local cache
  lastStatusMap.clear();
  return removed;
}
// Combined cancel + delete endpoint for frontend single action
app.post('/api/cancel-and-delete', auth, async (req,res)=>{
  try {
    await requestCancelAll();
    const removed = await bulkDeleteAll();
    // Invalidate any late SSE updates from previous generation by bumping generation and broadcasting purge event
    currentScanGeneration++;
    for(const res of sseClients){
      try { res.write(`event:purge\ndata:${JSON.stringify({ generation: currentScanGeneration })}\n\n`); } catch{}
    }
  cancelRequested=false; // allow future scans
  scanningPaused=true; // prevent cron from restarting implicitly
  res.json({ message:'Cancelled and deleted all data', screenshotsRemoved: removed, scanningPaused:true });
  } catch(e){
    res.status(500).json({ message:'Cancel+Delete failed', error:e.message });
  }
});
// Bulk delete all URL records & screenshots (after or independent of cancellation)
app.delete('/api/urls', auth, async (req,res)=>{
  try {
    await requestCancelAll(); // ensure no active work
    const removed = await bulkDeleteAll();
    cancelRequested=false; // allow future scans
    res.json({ message:'All URL records and screenshots deleted', screenshotsRemoved: removed });
  } catch(e){
    res.status(500).json({ message:'Bulk delete failed', error:e.message });
  }
});
app.delete('/api/urls/:id', auth, async (req,res)=>{ 
  const id = Number(req.params.id); 
  if (!Number.isInteger(id)) return res.status(400).json({ message:'Invalid id'});
  
  try { 
    // First get the record to extract screenshot URL for Cloudinary cleanup
    const { data: existingData, error: fetchError } = await supabase
      .from('urls')
      .select('screenshot_url')
      .eq('id', id)
      .single();
    
    if (fetchError && fetchError.code !== 'PGRST116') throw fetchError; // PGRST116 = not found
    
    // Delete from Cloudinary if screenshot exists
    if (existingData && existingData.screenshot_url) {
      await deleteCloudinaryScreenshot(existingData.screenshot_url);
    }
    
    // Delete from database
    const { data, error } = await supabase.from('urls').delete().eq('id',id).select(); 
    if (error) throw error; 
    if (!data || !data.length) return res.status(404).json({ message:'Not found'}); 
    
    res.json({ message:'Deleted', id }); 
  } catch(e){ 
    res.status(500).json({ message:'Delete failed', error:e.message }); 
  } 
});

// ---- CSV Export ----
// Export can follow same auth model as listing (urlsAuth) so public mode can download too
app.get('/api/export', urlsAuth, async (req,res)=>{
  try {
    const { data, error } = await supabase.from('urls').select('*').order('created_at',{ ascending:false });
    if(error) throw error;
    const rows = data || [];
    const headers = ['url','status','screenshot_url','ssl_expires_at','last_checked_at'];
    function esc(v){ if(v==null) return ''; const s=String(v); if(/[",\n]/.test(s)) return '"'+s.replace(/"/g,'""')+'"'; return s; }
    const csvLines = [ headers.join(',') ];
    for(const r of rows){
      csvLines.push(headers.map(h=>esc(r[h])).join(','));
    }
    const csvContent = csvLines.join('\n');
    res.setHeader('Content-Type','text/csv');
    res.setHeader('Content-Disposition','attachment; filename="urls_export.csv"');
    res.send(csvContent);
  } catch(e){
    res.status(500).json({ message:'Export failed', error:e.message });
  }
});

// ---- Manual Cleanup Endpoint ----
app.post('/api/cleanup-screenshots', auth, async (req,res)=>{
  try {
    const cleanedCount = await cleanupOldScreenshots();
    res.json({ 
      message: 'Screenshot cleanup completed', 
      cleanedFiles: cleanedCount 
    });
  } catch(e) {
    res.status(500).json({ 
      message: 'Cleanup failed', 
      error: e.message 
    });
  }
});

// ---- Migration Endpoint (Remove all legacy files immediately) ----
app.post('/api/migrate-screenshots', auth, async (req,res)=>{
  try {
    const files = await fs.readdir(SCREENSHOT_DIR);
    let migratedCount = 0;
    
    for(const file of files) {
      if(!file.endsWith('.png')) continue;
      
      // Remove ALL legacy formats: site-{id}.png and site-{id}-{timestamp}.png
      if(file.match(/^site-\d+(-\d{13})?\.png$/)) {
        const filePath = path.join(SCREENSHOT_DIR, file);
        try {
          await fs.unlink(filePath);
          migratedCount++;
          console.log(`[MIGRATE] Removed legacy file: ${file}`);
        } catch(e) {
          console.warn(`[MIGRATE] Failed to remove ${file}:`, e.message);
        }
      }
    }
    
    res.json({ 
      message: 'Migration completed - all legacy screenshots removed',
      migratedFiles: migratedCount,
      info: 'New URL-based naming (e.g., google.com.png) will be used going forward'
    });
  } catch(e) {
    res.status(500).json({ 
      message: 'Migration failed', 
      error: e.message 
    });
  }
});

// Root
app.get('/', (req,res)=>res.json({ service:'monitor', intervalMs:SCAN_INTERVAL_MS, scanCron: (process.env.SCAN_CRON ? process.env.SCAN_CRON.split('#')[0].trim() : '0 * * * *'), allowPublicSubmission: ALLOW_PUBLIC_SUBMISSION, scanningPaused, cancelRequested, generation: currentScanGeneration }));

// State introspection endpoint (admin only)
app.get('/api/state', auth, (req,res)=>{
  res.json({ scanningPaused, cancelRequested, generation: currentScanGeneration, cron: SCAN_CRON });
});

// Server-Sent Events stream
app.get('/api/stream', (req,res)=>{
  res.setHeader('Content-Type','text/event-stream');
  res.setHeader('Cache-Control','no-cache');
  res.setHeader('Connection','keep-alive');
  res.flushHeaders && res.flushHeaders();
  res.write('retry: 3000\n\n');
  sseClients.add(res);
  req.on('close',()=>{ sseClients.delete(res); });
});

// ---------------- Start Server ----------------
app.listen(PORT, ()=>console.log(`Monitoring server listening on ${PORT}`));

process.on('unhandledRejection', e=>console.error('[UNHANDLED]', e));
process.on('uncaughtException', e=>console.error('[UNCAUGHT]', e));
