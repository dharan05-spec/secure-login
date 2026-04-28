// Password strength indicator
const pwInput = document.getElementById('password');
const bars = document.querySelectorAll('.pw-bar');

if (pwInput && bars.length) {
  pwInput.addEventListener('input', () => {
    const val = pwInput.value;
    let score = 0;
    if (val.length >= 8) score++;
    if (/[A-Z]/.test(val)) score++;
    if (/[0-9]/.test(val)) score++;
    if (/[^A-Za-z0-9]/.test(val)) score++;

    bars.forEach((bar, i) => {
      bar.className = 'pw-bar';
      if (score === 1 && i === 0) bar.classList.add('weak');
      if (score === 2 && i <= 1) bar.classList.add('medium');
      if (score >= 3 && i <= 2) bar.classList.add('strong');
      if (score === 4) bar.classList.add('strong');
    });
  });
}

// OTP input: digits only, max 6
const otpInput = document.querySelector('.otp-input');
if (otpInput) {
  otpInput.addEventListener('input', () => {
    otpInput.value = otpInput.value.replace(/\D/g, '').slice(0, 6);
  });
  otpInput.focus();
}
