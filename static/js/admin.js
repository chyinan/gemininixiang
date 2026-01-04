/* ============================================
   管理后台 JavaScript
   ============================================ */

// 全局配置
const CONFIG = {
    API_KEY: '',
    PORT: 23456
};

// Cookie 字段映射
const COOKIE_FIELDS = {
    '__Secure-1PSID': 'SECURE_1PSID',
    '__Secure-1PSIDTS': 'SECURE_1PSIDTS',
    'SAPISID': 'SAPISID',
    '__Secure-1PAPISID': 'SECURE_1PAPISID',
    'SID': 'SID',
    'HSID': 'HSID',
    'SSID': 'SSID',
    'APISID': 'APISID'
};

// 初始化
document.addEventListener('DOMContentLoaded', function() {
    initializeConfig();
    initializeCookieParser();
    initializeModelIdParser();
    initializeForm();
    initializeImageModal();
    updateApiInfo();
});

// 初始化配置
function initializeConfig() {
    // 从服务器获取配置（如果可用）
    fetch('/admin/config', { credentials: 'same-origin' })
        .then(r => {
            if (!r.ok) throw new Error('未登录');
            return r.json();
        })
        .then(config => {
            // 加载 Cookie
            if (config.FULL_COOKIE) {
                document.getElementById('FULL_COOKIE').value = config.FULL_COOKIE;
                showParsedFields(parseCookie(config.FULL_COOKIE));
            }
            
            // 加载手动输入的 AT Token
            if (config.MANUAL_SNLM0E) {
                document.getElementById('MANUAL_SNLM0E').value = config.MANUAL_SNLM0E;
            }
            
            // 加载手动输入的 PUSH_ID
            if (config.MANUAL_PUSH_ID) {
                document.getElementById('MANUAL_PUSH_ID').value = config.MANUAL_PUSH_ID;
            }
            
            // 加载模型 ID
            if (config.MODEL_IDS) {
                document.getElementById('MODEL_ID_FLASH').value = config.MODEL_IDS.flash || '';
                document.getElementById('MODEL_ID_PRO').value = config.MODEL_IDS.pro || '';
                document.getElementById('MODEL_ID_THINKING').value = config.MODEL_IDS.thinking || '';
            }
        })
        .catch(err => {
            console.log('加载配置失败:', err);
        });
}

// 初始化 Cookie 解析器
function initializeCookieParser() {
    const cookieInput = document.getElementById('FULL_COOKIE');
    if (!cookieInput) return;
    
    // 使用防抖优化性能
    const debouncedParse = CommonUtils.debounce((value) => {
        const parsed = parseCookie(value);
        showParsedFields(parsed);
    }, 300);
    
    cookieInput.addEventListener('input', (e) => {
        debouncedParse(e.target.value);
    });
}

// 解析 Cookie 字符串
function parseCookie(cookieStr) {
    const result = {};
    if (!cookieStr) return result;
    
    cookieStr.split(';').forEach(item => {
        const trimmed = item.trim();
        const eqIndex = trimmed.indexOf('=');
        if (eqIndex > 0) {
            const key = trimmed.substring(0, eqIndex).trim();
            const value = trimmed.substring(eqIndex + 1).trim();
            if (COOKIE_FIELDS[key]) {
                result[COOKIE_FIELDS[key]] = value;
            }
        }
    });
    return result;
}

// 显示解析的字段
function showParsedFields(parsed) {
    const container = document.getElementById('parsedFields');
    const infoBox = document.getElementById('parsedInfo');
    
    if (!container || !infoBox) return;
    
    const fieldNames = {
        'SECURE_1PSID': '__Secure-1PSID',
        'SECURE_1PSIDTS': '__Secure-1PSIDTS',
        'SAPISID': 'SAPISID',
        'SID': 'SID',
        'HSID': 'HSID',
        'SSID': 'SSID',
        'APISID': 'APISID'
    };
    
    let html = '';
    let hasFields = false;
    
    for (const [key, name] of Object.entries(fieldNames)) {
        if (parsed[key]) {
            hasFields = true;
            const shortValue = parsed[key].length > 30 
                ? parsed[key].substring(0, 30) + '...' 
                : parsed[key];
            html += `<div class="item">${name}: <span>${shortValue}</span></div>`;
        }
    }
    
    if (hasFields) {
        container.innerHTML = html;
        infoBox.style.display = 'block';
    } else {
        infoBox.style.display = 'none';
    }
}

// 初始化模型 ID 解析器
function initializeModelIdParser() {
    const parserInput = document.getElementById('MODEL_ID_PARSER');
    if (!parserInput) return;
    
    parserInput.addEventListener('input', (e) => {
        const modelId = parseModelId(e.target.value);
        const container = document.getElementById('parsedModelIdValue');
        const infoBox = document.getElementById('parsedModelId');
        
        if (!container || !infoBox) return;
        
        if (modelId) {
            container.innerHTML = `
                <div class="item">提取到的 ID: <span>${modelId}</span></div>
                <div class="quick-action-buttons" style="margin-top:10px;">
                    <button type="button" class="quick-action-btn" onclick="fillModelId('flash', '${modelId}')">填入极速版</button>
                    <button type="button" class="quick-action-btn" onclick="fillModelId('pro', '${modelId}')">填入Pro版</button>
                    <button type="button" class="quick-action-btn" onclick="fillModelId('thinking', '${modelId}')">填入思考版</button>
                </div>
            `;
            infoBox.style.display = 'block';
        } else {
            infoBox.style.display = 'none';
        }
    });
}

// 解析模型 ID
function parseModelId(input) {
    try {
        const arr = JSON.parse(input);
        if (Array.isArray(arr) && arr.length > 4 && typeof arr[4] === 'string') {
            return arr[4];
        }
    } catch (e) {
        const match = input.match(/["']([a-f0-9]{16})["']/i);
        if (match) {
            return match[1];
        }
    }
    return null;
}

// 填入模型 ID
function fillModelId(type, id) {
    const fieldMap = {
        'flash': 'MODEL_ID_FLASH',
        'pro': 'MODEL_ID_PRO',
        'thinking': 'MODEL_ID_THINKING'
    };
    const field = document.getElementById(fieldMap[type]);
    if (field) {
        field.value = id;
        field.style.borderColor = 'var(--success)';
        setTimeout(() => {
            field.style.borderColor = '';
        }, 2000);
    }
}

// 初始化表单
function initializeForm() {
    const configForm = document.getElementById('configForm');
    if (!configForm) return;
    
    configForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // 验证表单
        if (!CommonUtils.validateForm(configForm)) {
            CommonUtils.showError('请填写所有必填字段');
            return;
        }
        
        const formData = new FormData(configForm);
        const data = Object.fromEntries(formData.entries());
        
        // 构建模型 ID 对象
        data.MODEL_IDS = {
            flash: data.MODEL_ID_FLASH || '',
            pro: data.MODEL_ID_PRO || '',
            thinking: data.MODEL_ID_THINKING || ''
        };
        delete data.MODEL_ID_FLASH;
        delete data.MODEL_ID_PRO;
        delete data.MODEL_ID_THINKING;
        
        const statusEl = document.getElementById('status');
        const submitBtn = configForm.querySelector('button[type="submit"]');
        const originalText = submitBtn.textContent;
        
        // 显示保存中状态
        CommonUtils.showLoading(submitBtn);
        statusEl.style.display = 'none';
        
        try {
            const resp = await fetch('/admin/save', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'same-origin',
                body: JSON.stringify(data)
            });
            
            if (resp.status === 401) {
                window.location.href = '/admin/login';
                return;
            }
            
            const result = await resp.json();
            
            if (result.success) {
                CommonUtils.showSuccess(result.message + '\n\n💡 配置已生效，无需重启服务！');
            } else {
                CommonUtils.showError(result.message);
            }
        } catch (err) {
            CommonUtils.showError('保存失败: ' + err.message);
        } finally {
            CommonUtils.hideLoading(submitBtn, originalText);
        }
    });
}

// 初始化图片模态框
function initializeImageModal() {
    const modal = document.getElementById('imageModal');
    if (!modal) return;
    
    // 点击背景关闭
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            hideImageModal();
        }
    });
    
    // ESC 键关闭
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            hideImageModal();
        }
    });
}

// 显示图片模态框
function showImageModal() {
    const modal = document.getElementById('imageModal');
    if (modal) {
        modal.classList.add('show');
        document.body.style.overflow = 'hidden';
    }
}

// 隐藏图片模态框
function hideImageModal() {
    const modal = document.getElementById('imageModal');
    if (modal) {
        modal.classList.remove('show');
        document.body.style.overflow = 'auto';
    }
}

// 更新 API 信息
function updateApiInfo() {
    // 从全局CONFIG对象读取（由模板注入）
    const port = window.CONFIG?.PORT || CONFIG.PORT || 23456;
    const apiKey = window.CONFIG?.API_KEY || CONFIG.API_KEY || 'sk-gemini';
    const baseUrl = `http://localhost:${port}/v1`;
    
    // 更新显示
    const baseUrlEl = document.getElementById('baseUrl');
    const apiKeyEl = document.getElementById('apiKey');
    const codeUrlEls = document.querySelectorAll('#codeUrl, #codeUrl2');
    const codeKeyEls = document.querySelectorAll('#codeKey, #codeKey2');
    
    if (baseUrlEl) baseUrlEl.textContent = baseUrl;
    if (apiKeyEl) apiKeyEl.textContent = apiKey;
    codeUrlEls.forEach(el => { if (el) el.textContent = baseUrl; });
    codeKeyEls.forEach(el => { if (el) el.textContent = apiKey; });
}

// 导出函数供 HTML 使用
window.showImageModal = showImageModal;
window.hideImageModal = hideImageModal;
window.fillModelId = fillModelId;

