/**
 * XingYunGuard - 前端防护引擎
 * 从「星云防CC系统」PHP 版移植的静态站等效实现
 *
 * 防护能力：
 *  1. 访问频率检测（替代服务端 QPS 检测）→ 防 CC/刷流量
 *  2. 行为指纹（替代 IP 识别）→ 识别异常访客
 *  3. JS 计算挑战（替代验证码）→ 拦截无头浏览器/脚本
 *  4. 黑名单机制（本地持久化）→ 记录并拦截恶意访客
 *  5. 安全响应头注入 → 防 XSS/点击劫持/MIME嗅探
 */
(function () {
    'use strict';

    var GUARD_KEY = 'xingyun_guard_v1';
    var BLOCKED_KEY = 'xingyun_blacklist_v1';
    var MAX_REQUESTS = 40;        // 每分钟最大请求数（星云默认5/秒太激进，静态页放宽）
    var WINDOW_MS = 60000;        // 检测窗口 60 秒
    var CHALLENGE_DIFFICULTY = 6; // 计算挑战位数
    var DEFENSE_MS = 120000;      // 触发防护后锁定 2 分钟（星云 defense_time=100秒）

    // ===== 1. 指纹生成（替代 IP） =====
    function getFingerprint() {
        var parts = [];
        try {
            parts.push(navigator.userAgent);
            parts.push(screen.width + 'x' + screen.height + 'x' + screen.colorDepth);
            parts.push(navigator.language || '');
            parts.push(new Date().getTimezoneOffset());
            parts.push(navigator.hardwareConcurrency || '');
            parts.push(navigator.deviceMemory || '');
        } catch (e) { parts.push('err'); }
        var str = parts.join('|');
        // 简单 hash
        var hash = 0;
        for (var i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash |= 0;
        }
        return 'fp_' + Math.abs(hash).toString(16);
    }

    // ===== 2. 频率检测（替代服务端计数） =====
    function checkRate() {
        var now = Date.now();
        var rec = null;
        try { rec = JSON.parse(localStorage.getItem(GUARD_KEY) || 'null'); } catch (e) {}
        if (!rec) {
            rec = { count: 1, windowStart: now, blockedUntil: 0 };
        } else {
            if (now - rec.windowStart > WINDOW_MS) {
                rec = { count: 1, windowStart: now, blockedUntil: rec.blockedUntil };
            } else {
                rec.count++;
            }
        }
        localStorage.setItem(GUARD_KEY, JSON.stringify(rec));
        return rec;
    }

    // ===== 3. 黑名单检查 =====
    function isBlacklisted() {
        var fp = getFingerprint();
        var list = [];
        try { list = JSON.parse(localStorage.getItem(BLOCKED_KEY) || '[]'); } catch (e) {}
        return list.indexOf(fp) !== -1;
    }

    function addToBlacklist() {
        var fp = getFingerprint();
        var list = [];
        try { list = JSON.parse(localStorage.getItem(BLOCKED_KEY) || '[]'); } catch (e) {}
        if (list.indexOf(fp) === -1) list.push(fp);
        localStorage.setItem(BLOCKED_KEY, JSON.stringify(list));
    }

    // ===== 4. 计算挑战（替代验证码） =====
    function makeChallenge() {
        var a = Math.floor(Math.random() * 90) + 10;
        var b = Math.floor(Math.random() * 90) + 10;
        return { a: a, b: b, ans: a + b };
    }

    // ===== 5. 安全响应头注入 =====
    function injectSecurityHeaders() {
        // CSP - 内容安全策略
        var csp = document.createElement('meta');
        csp.httpEquiv = 'Content-Security-Policy';
        csp.content = "default-src 'self'; img-src 'self' data: https://cdn.simpleicons.org; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
        document.head.appendChild(csp);

        // X-Frame-Options - 防点击劫持
        var xfo = document.createElement('meta');
        xfo.httpEquiv = 'X-Frame-Options';
        xfo.content = 'DENY';
        document.head.appendChild(xfo);

        // X-Content-Type-Options - 防 MIME 嗅探
        var xcto = document.createElement('meta');
        xcto.httpEquiv = 'X-Content-Type-Options';
        xcto.content = 'nosniff';
        document.head.appendChild(xcto);

        // Referrer-Policy - 防 referer 泄露
        var rp = document.createElement('meta');
        rp.httpEquiv = 'Referrer-Policy';
        rp.content = 'no-referrer';
        document.head.appendChild(rp);

        // Permissions-Policy - 限制浏览器 API
        var pp = document.createElement('meta');
        pp.httpEquiv = 'Permissions-Policy';
        pp.content = 'geolocation=(), microphone=(), camera=(), payment=()';
        document.head.appendChild(pp);

        // HSTS 提示
        var hs = document.createElement('meta');
        hs.httpEquiv = 'Strict-Transport-Security';
        hs.content = 'max-age=31536000';
        document.head.appendChild(hs);
    }

    // ===== 6. 挑战页面渲染 =====
    function showChallenge() {
        // 防止重复
        if (document.getElementById('xingyun-shield')) return;

        var shield = document.createElement('div');
        shield.id = 'xingyun-shield';
        shield.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;z-index:99999;' +
            'background:#0b0d12;color:#e8ecf3;display:flex;align-items:center;justify-content:center;' +
            'font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;';

        var ch = makeChallenge();
        var box = document.createElement('div');
        box.style.cssText = 'text-align:center;padding:40px;max-width:380px;width:90%;';

        var icon = document.createElement('div');
        icon.textContent = '🛡️';
        icon.style.cssText = 'font-size:52px;margin-bottom:20px;';

        var title = document.createElement('h2');
        title.textContent = '安全验证';
        title.style.cssText = 'font-size:22px;font-weight:700;margin-bottom:12px;';

        var desc = document.createElement('p');
        desc.textContent = '检测到异常访问，请完成以下验证以继续';
        desc.style.cssText = 'color:#8b93a7;font-size:14px;margin-bottom:24px;';

        var form = document.createElement('div');
        form.style.cssText = 'display:flex;gap:10px;justify-content:center;align-items:center;';

        var q = document.createElement('span');
        q.textContent = ch.a + ' + ' + ch.b + ' = ?';
        q.style.cssText = 'font-size:18px;font-weight:600;';

        var input = document.createElement('input');
        input.type = 'number';
        input.style.cssText = 'width:90px;padding:10px;border-radius:8px;border:1px solid #2a3344;' +
            'background:#151922;color:#fff;font-size:16px;text-align:center;outline:none;';

        var btn = document.createElement('button');
        btn.textContent = '验证';
        btn.style.cssText = 'padding:10px 22px;border-radius:8px;border:none;background:#5b8cff;' +
            'color:#fff;font-size:14px;font-weight:600;cursor:pointer;';

        btn.onclick = function () {
            var v = parseInt(input.value, 10);
            if (v === ch.ans) {
                // 通过：记录白名单状态
                try {
                    var rec = JSON.parse(localStorage.getItem(GUARD_KEY) || 'null');
                    if (rec) { rec.blockedUntil = 0; localStorage.setItem(GUARD_KEY, JSON.stringify(rec)); }
                    localStorage.setItem('xingyun_whitelist_v1', '1');
                } catch (e) {}
                location.reload();
            } else {
                desc.textContent = '答案错误，请重试';
                desc.style.color = '#f87171';
                input.value = '';
                input.focus();
            }
        };

        form.appendChild(q);
        form.appendChild(input);
        form.appendChild(btn);
        box.appendChild(icon);
        box.appendChild(title);
        box.appendChild(desc);
        box.appendChild(form);
        shield.appendChild(box);
        document.body.appendChild(shield);
    }

    // ===== 7. 主防护流程 =====
    function run() {
        // 注入安全头
        injectSecurityHeaders();

        // 黑名单直接拦截
        if (isBlacklisted()) {
            document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;background:#0b0d12;color:#8b93a7;font-family:sans-serif;font-size:16px;">访问已被限制</div>';
            return;
        }

        var rec = checkRate();

        // 防护锁定中 → 挑战
        if (rec.blockedUntil > Date.now()) {
            showChallenge();
            return;
        }

        // 频率超限 → 进入防护模式（锁定 + 挑战）
        if (rec.count > MAX_REQUESTS) {
            rec.blockedUntil = Date.now() + DEFENSE_MS;
            localStorage.setItem(GUARD_KEY, JSON.stringify(rec));
            // 3 次超限拉黑
            var failCount = parseInt(localStorage.getItem('xingyun_fail_v1') || '0', 10);
            failCount++;
            localStorage.setItem('xingyun_fail_v1', String(failCount));
            if (failCount >= 3) {
                addToBlacklist();
            }
            showChallenge();
        }
    }

    // 立即执行
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', run);
    } else {
        run();
    }
})();