/* ============================================
   通用 JavaScript 工具函数
   ============================================ */

// 显示状态消息
function showStatus(message, type = 'success') {
    const statusEl = document.getElementById('status');
    if (!statusEl) return;
    
    statusEl.className = `status ${type}`;
    statusEl.textContent = message;
    statusEl.style.display = 'block';
    
    // 自动隐藏成功消息
    if (type === 'success') {
        setTimeout(() => {
            statusEl.style.display = 'none';
        }, 5000);
    }
}

// 显示错误消息
function showError(message) {
    showStatus(message, 'error');
}

// 显示成功消息
function showSuccess(message) {
    showStatus(message, 'success');
}

// 格式化日期时间
function formatDateTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString('zh-CN');
}

// 复制到剪贴板
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch (err) {
        // 降级方案
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            document.body.removeChild(textarea);
            return true;
        } catch (e) {
            document.body.removeChild(textarea);
            return false;
        }
    }
}

// 显示复制成功提示
function showCopySuccess(button) {
    const originalText = button.textContent;
    button.textContent = '✓ 已复制';
    button.classList.add('copied');
    
    setTimeout(() => {
        button.textContent = originalText;
        button.classList.remove('copied');
    }, 2000);
}

// 防抖函数
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// 节流函数
function throttle(func, limit) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// 验证表单
function validateForm(formElement) {
    const requiredFields = formElement.querySelectorAll('[required]');
    let isValid = true;
    
    requiredFields.forEach(field => {
        if (!field.value.trim()) {
            field.style.borderColor = 'var(--error)';
            isValid = false;
        } else {
            field.style.borderColor = '';
        }
    });
    
    return isValid;
}

// 重置表单验证样式
function resetFormValidation(formElement) {
    const fields = formElement.querySelectorAll('input, textarea');
    fields.forEach(field => {
        field.style.borderColor = '';
    });
}

// 加载动画
function showLoading(button) {
    button.disabled = true;
    button.innerHTML = '<span class="loading"></span>处理中...';
}

function hideLoading(button, originalText) {
    button.disabled = false;
    button.textContent = originalText;
}

// 平滑滚动
function smoothScrollTo(element) {
    element.scrollIntoView({
        behavior: 'smooth',
        block: 'start'
    });
}

// 格式化文件大小
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// 导出函数供其他脚本使用
window.CommonUtils = {
    showStatus,
    showError,
    showSuccess,
    formatDateTime,
    copyToClipboard,
    showCopySuccess,
    debounce,
    throttle,
    validateForm,
    resetFormValidation,
    showLoading,
    hideLoading,
    smoothScrollTo,
    formatFileSize
};

