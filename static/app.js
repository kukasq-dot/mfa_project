// --- 1. УПРАВЛЕНИЕ UI И СОСТОЯНИЕМ ---
window.onload = function() { checkAuthStatus(); };

async function checkAuthStatus() {
    try {
        const response = await fetch("/auth/status");
        if (response.ok) {
            document.getElementById("auth-view").style.display = "none";
            document.getElementById("dashboard-view").style.display = "block";
            resetAuthForms();
        } else {
            document.getElementById("auth-view").style.display = "block";
            document.getElementById("dashboard-view").style.display = "none";
        }
    } catch(e) {
        console.error("Ошибка проверки статуса");
    }
}

function switchTab(tabName) {
    // Скрываем все сообщения при переключении
    document.getElementById("message-auth").classList.remove('active');
    document.getElementById("message-reg").classList.remove('active');
    document.getElementById("loginMfaBlock").classList.remove("active");
    
    // Меняем активную вкладку
    document.getElementById("tab-login").classList.remove("active");
    document.getElementById("tab-register").classList.remove("active");
    document.getElementById("tab-" + tabName).classList.add("active");

    // Показываем нужную форму
    document.getElementById("login-form").classList.remove("active");
    document.getElementById("register-form").classList.remove("active");
    document.getElementById(tabName + "-form").classList.add("active");
}

function togglePassword(inputId, iconElement) {
    const input = document.getElementById(inputId);
    if (input.type === "password") {
        input.type = "text";
        iconElement.innerText = "🙈";
    } else {
        input.type = "password";
        iconElement.innerText = "👁️";
    }
}

function resetAuthForms() {
    document.getElementById("login-username").value = "";
    document.getElementById("login-password").value = "";
    document.getElementById("loginMfaCode").value = "";
    document.getElementById("reg-username").value = "";
    document.getElementById("reg-password").value = "";
    document.getElementById("reg-password-confirm").value = "";
    
    // ИСЧЕЗНОВЕНИЕ ПОЧИНЕНО ЗДЕСЬ: используем классы вместо style.display
    document.getElementById("password-rules").classList.remove("active");
    document.getElementById("loginMfaBlock").classList.remove("active");
}

function showMsg(elementId, msg, type) {
    const el = document.getElementById(elementId);
    // Удаляем старые классы сообщений
    el.classList.remove('success', 'error', 'info', 'active');
    
    // Добавляем красивый класс в зависимости от типа
    if (type === 'green') el.classList.add('success');
    else if (type === 'red') el.classList.add('error');
    else el.classList.add('info'); 
    
    el.innerText = msg;
    el.classList.add('active'); // Активируем плавное появление
    
    setTimeout(() => { 
        el.classList.remove('active'); 
    }, 6000); 
}

function setButtonLoading(buttonId, isLoading, defaultText) {
    const btn = document.getElementById(buttonId);
    if (isLoading) {
        btn.disabled = true;
        btn.innerText = "Ожидание...";
    } else {
        btn.disabled = false;
        btn.innerText = defaultText;
    }
}

// --- 2. ДИНАМИЧЕСКАЯ ВАЛИДАЦИЯ ПАРОЛЯ ---
function updateRuleUI(ruleId, isValid) {
    const el = document.getElementById(ruleId);
    const icon = el.querySelector('.check-icon');
    
    // Обновляем кружочки на красивые галочки
    if (isValid) {
        el.classList.add("valid");
        icon.innerText = "✓";
    } else {
        el.classList.remove("valid");
        icon.innerText = "◯";
    }
}

function validatePassword() {
    const pwd = document.getElementById("reg-password").value;
    const confirmPwd = document.getElementById("reg-password-confirm").value;
    const rulesBox = document.getElementById("password-rules");
    
    // Показываем блок с правилами при вводе (через CSS-класс!)
    if (pwd.length > 0) rulesBox.classList.add("active");
    else rulesBox.classList.remove("active");

    // Проверяем правила
    const hasLength = pwd.length >= 8;
    const hasLetter = /[a-zA-Zа-яА-Я]/.test(pwd);
    const hasNumber = /\d/.test(pwd);
    const noSpaces = !/\s/.test(pwd) && pwd.length > 0;
    const isMatch = (pwd === confirmPwd) && (pwd.length > 0);

    updateRuleUI("rule-length", hasLength);
    updateRuleUI("rule-letter", hasLetter);
    updateRuleUI("rule-number", hasNumber);
    updateRuleUI("rule-space", noSpaces); 
    updateRuleUI("rule-match", isMatch);

    return hasLength && hasLetter && hasNumber && noSpaces && isMatch;
}

// --- 3. АВТОРИЗАЦИЯ И РЕГИСТРАЦИЯ ---
function parseError(errorData) {
    if (Array.isArray(errorData.detail)) return "Пожалуйста, проверьте правильность данных.";
    return errorData.detail || "Неизвестная ошибка сервера";
}

async function register() {
    const u = document.getElementById("reg-username").value.trim();
    const p = document.getElementById("reg-password").value.trim();

    if (!u) { showMsg("message-reg", "Введите логин", "red"); return; }
    if (!validatePassword()) { showMsg("message-reg", "Пароль не соответствует требованиям", "red"); return; }

    setButtonLoading("btn-register", true, "Создать аккаунт");

    try {
        const response = await fetch("/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: u, password: p })
        });

        if (response.ok) {
            showMsg("message-auth", "Регистрация успешна! Выполните вход.", "green");
            switchTab('login'); 
            document.getElementById("login-username").value = u;
        } else {
            const error = await response.json();
            showMsg("message-reg", parseError(error), "red");
        }
    } catch (e) {
        showMsg("message-reg", "Ошибка сети", "red");
    } finally {
        setButtonLoading("btn-register", false, "Создать аккаунт");
    }
}

async function login() {
    const u = document.getElementById("login-username").value.trim();
    const p = document.getElementById("login-password").value.trim();

    if (!u || !p) { showMsg("message-auth", "Введите логин и пароль.", "red"); return; }

    setButtonLoading("btn-login", true, "Войти в систему");

    const formData = new URLSearchParams();
    formData.append("username", u);
    formData.append("password", p);

    try {
        const response = await fetch("/login", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: formData
        });

        if (response.ok) {
            const data = await response.json();
            if (data.mfa_required) {
                // Плавно показываем блок MFA
                document.getElementById("loginMfaBlock").classList.add("active");
                showMsg("message-auth", data.message, "info");
            } else {
                completeLogin();
            }
        } else {
            const error = await response.json();
            showMsg("message-auth", parseError(error), "red");
        }
    } catch (e) {
        showMsg("message-auth", "Ошибка соединения", "red");
    } finally {
        setButtonLoading("btn-login", false, "Войти в систему");
    }
}

async function loginWithMfa() {
    const u = document.getElementById("login-username").value.trim();
    const p = document.getElementById("login-password").value.trim();
    const code = document.getElementById("loginMfaCode").value.trim();

    if (!code || (code.length !== 6 && code.length !== 8)) { 
        showMsg("message-auth", "Введите 6-значный код из приложения или 8-значный резервный код.", "red"); 
        return; 
    }

    setButtonLoading("btn-login-mfa", true, "Подтвердить вход");

    const formData = new URLSearchParams();
    formData.append("username", u);
    formData.append("password", p);
    formData.append("mfa_code", code);

    try {
        const response = await fetch("/login", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: formData
        });

        if (response.ok) {
            completeLogin();
        } else {
            const error = await response.json();
            showMsg("message-auth", parseError(error), "red");
        }
    } catch (e) {
        showMsg("message-auth", "Ошибка сети", "red");
    } finally {
        setButtonLoading("btn-login-mfa", false, "Подтвердить вход");
    }
}

function completeLogin() {
    checkAuthStatus();
    // Небольшая задержка, чтобы успел прорисоваться дашборд
    setTimeout(() => showMsg("message-dash", "Успешный вход!", "green"), 300);
}

async function logout() {
    await fetch("/logout", { method: "POST" });
    showMsg("message-auth", "Вы успешно вышли из системы", "green");
    checkAuthStatus();
}

// --- 4. ЗАЩИЩЕННЫЕ ОПЕРАЦИИ (ЛИЧНЫЙ КАБИНЕТ) ---
async function getSecretData() {
    const response = await fetch("/protected_data", { method: "GET" });

    if (response.ok) {
        const data = await response.json();
        showMsg("message-dash", "Доступ разрешен: " + data.message, "green");
    } else {
        logout();
        showMsg("message-auth", "Сессия истекла. Войдите заново.", "red");
    }
}

async function setupMFA() {
    const response = await fetch("/mfa/setup", { method: "GET" });

    if (response.ok) {
        const data = await response.json();
        document.getElementById("mfaSetupBlock").classList.add("active");
        document.getElementById("qrCodeImage").src = data.qr_code_url;
        document.getElementById("qrCodeImage").style.display = "block";
    } else {
        const error = await response.json();
        showMsg("message-dash", "Внимание: " + error.detail, "red");
    }
}

async function verifyMFA() {
    const code = document.getElementById("mfaCode").value;
    
    setButtonLoading("btn-verify-mfa", true, "Подтвердить привязку");

    try {
        const response = await fetch("/mfa/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code: code })
        });

        if (response.ok) {
            const data = await response.json();
            showMsg("message-dash", data.message, "green");
            
            // Если сервер прислал резервные коды, красиво их отображаем
            if (data.backup_codes) {
                document.getElementById("backupCodesBlock").classList.add("active");
                const ul = document.getElementById("backupCodesList");
                ul.innerHTML = "";
                data.backup_codes.forEach(code => {
                    const div = document.createElement("div");
                    div.className = "backup-code";
                    div.innerText = code;
                    ul.appendChild(div);
                });
                
                // Прячем всё лишнее, чтобы пользователь сосредоточился на кодах
                document.getElementById("mfaCode").style.display = "none";
                document.getElementById("btn-verify-mfa").style.display = "none";
                document.getElementById("qrCodeImage").style.display = "none";
                document.querySelector("#mfaSetupBlock .mfa-title").innerText = "Настройка завершена";
                document.querySelector("#mfaSetupBlock .mfa-desc").style.display = "none";
            }
        } else {
            const error = await response.json();
            showMsg("message-dash", error.detail, "red");
        }
    } catch (e) {
        showMsg("message-dash", "Ошибка сети", "red");
    } finally {
        setButtonLoading("btn-verify-mfa", false, "Подтвердить привязку");
    }
}