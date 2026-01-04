/* ============================================
   登录页面 JavaScript
   ============================================ */

document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');
    const errorEl = document.getElementById('error');
    const submitBtn = document.getElementById('submitBtn');
    
    if (!loginForm) return;
    
    // 表单提交处理
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // 隐藏之前的错误
        errorEl.classList.remove('show');
        errorEl.textContent = '';
        
        // 验证表单
        if (!CommonUtils.validateForm(loginForm)) {
            errorEl.textContent = '请填写所有必填字段';
            errorEl.classList.add('show');
            return;
        }
        
        // 显示加载状态
        const originalText = submitBtn.textContent;
        CommonUtils.showLoading(submitBtn);
        
        try {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            const resp = await fetch('/admin/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });
            
            const result = await resp.json();
            
            if (result.success) {
                // 登录成功，跳转
                window.location.href = '/admin';
            } else {
                // 显示错误
                errorEl.textContent = result.message || '登录失败，请检查用户名和密码';
                errorEl.classList.add('show');
                CommonUtils.hideLoading(submitBtn, originalText);
            }
        } catch (err) {
            errorEl.textContent = '网络错误: ' + err.message;
            errorEl.classList.add('show');
            CommonUtils.hideLoading(submitBtn, originalText);
        }
    });
    
    // 输入框焦点效果
    const inputs = loginForm.querySelectorAll('input');
    inputs.forEach(input => {
        input.addEventListener('focus', function() {
            this.parentElement.style.transform = 'scale(1.02)';
        });
        
        input.addEventListener('blur', function() {
            this.parentElement.style.transform = 'scale(1)';
        });
    });
    
    // Enter 键快速提交
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && document.activeElement.tagName !== 'BUTTON') {
            loginForm.dispatchEvent(new Event('submit'));
        }
    });
});

