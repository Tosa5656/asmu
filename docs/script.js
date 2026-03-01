(function() {
    'use strict';

    const canvas = document.getElementById('particles');
    if (canvas) {
        const ctx = canvas.getContext('2d');
        let particles = [];
        let animationId = null;

        function resizeCanvas() {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        }

        function createParticle() {
            return {
                x: Math.random() * canvas.width,
                y: Math.random() * canvas.height,
                vx: (Math.random() - 0.5) * 0.3,
                vy: (Math.random() - 0.5) * 0.3,
                radius: Math.random() * 1.5 + 0.5,
                opacity: Math.random() * 0.5 + 0.2
            };
        }

        function initParticles() {
            particles = [];
            const count = Math.floor((canvas.width * canvas.height) / 20000);
            for (let i = 0; i < count; i++) {
                particles.push(createParticle());
            }
        }

        function updateParticles() {
            particles.forEach(p => {
                p.x += p.vx;
                p.y += p.vy;

                if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
                if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

                p.x = Math.max(0, Math.min(canvas.width, p.x));
                p.y = Math.max(0, Math.min(canvas.height, p.y));
            });
        }

        function drawParticles() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            particles.forEach(p => {
                ctx.globalAlpha = p.opacity;
                ctx.fillStyle = '#00d9ff';
                ctx.beginPath();
                ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
                ctx.fill();
            });

            ctx.globalAlpha = 0.1;
            particles.forEach((p, i) => {
                for (let j = i + 1; j < particles.length; j++) {
                    const p2 = particles[j];
                    const dx = p.x - p2.x;
                    const dy = p.y - p2.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 150) {
                        ctx.strokeStyle = '#00d9ff';
                        ctx.lineWidth = 0.5;
                        ctx.beginPath();
                        ctx.moveTo(p.x, p.y);
                        ctx.lineTo(p2.x, p2.y);
                        ctx.stroke();
                    }
                }
            });

            ctx.globalAlpha = 1;
        }

        function animateParticles() {
            updateParticles();
            drawParticles();
            animationId = requestAnimationFrame(animateParticles);
        }

        resizeCanvas();
        initParticles();
        animateParticles();

        window.addEventListener('resize', () => {
            resizeCanvas();
            initParticles();
        });
    }

    const navToggle = document.getElementById('nav-toggle');
    const navLinks = document.getElementById('nav-links');

    if (navToggle && navLinks) {
        navToggle.addEventListener('click', () => {
            navLinks.classList.toggle('active');
            navToggle.setAttribute('aria-expanded',
                navLinks.classList.contains('active'));
        });

        document.addEventListener('click', (e) => {
            if (navLinks.classList.contains('active') &&
                !navToggle.contains(e.target) &&
                !navLinks.contains(e.target)) {
                navLinks.classList.remove('active');
                navToggle.setAttribute('aria-expanded', 'false');
            }
        });

        window.addEventListener('resize', () => {
            if (window.innerWidth > 768) {
                navLinks.classList.remove('active');
                navToggle.setAttribute('aria-expanded', 'false');
            }
        });
    }

    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            const href = this.getAttribute('href');
            if (href === '#') return;

            const target = document.querySelector(href);
            if (target) {
                e.preventDefault();
                const headerHeight = 70;
                const targetPosition = target.getBoundingClientRect().top + window.scrollY - headerHeight;

                window.scrollTo({
                    top: targetPosition,
                    behavior: 'smooth'
                });

                if (navLinks && navLinks.classList.contains('active')) {
                    navLinks.classList.remove('active');
                    if (navToggle) {
                        navToggle.setAttribute('aria-expanded', 'false');
                    }
                }
            }
        });
    });

    function animateNumber(element) {
        const target = parseInt(element.getAttribute('data-target'));
        const duration = 2000;
        const start = Date.now();
        const startVal = 0;

        function update() {
            const now = Date.now();
            const elapsed = now - start;
            const progress = Math.min(elapsed / duration, 1);
            const easeOut = 1 - Math.pow(1 - progress, 3);
            const current = Math.floor(startVal + (target - startVal) * easeOut);
            element.textContent = current;

            if (progress < 1) {
                requestAnimationFrame(update);
            } else {
                element.textContent = target;
            }
        }

        update();
    }

    
    const statNumbers = document.querySelectorAll('.stat-value[data-target]');
    let statsAnimated = false;

    function checkStats() {
        if (statsAnimated) return;

        const heroSection = document.querySelector('.hero');
        if (!heroSection) return;

        const rect = heroSection.getBoundingClientRect();
        if (rect.top < window.innerHeight && rect.bottom > 0) {
            statNumbers.forEach(el => animateNumber(el));
            statsAnimated = true;
        }
    }

    const backToTop = document.getElementById('back-to-top');

    function updateBackToTop() {
        if (backToTop) {
            if (window.scrollY > 400) {
                backToTop.classList.add('visible');
            } else {
                backToTop.classList.remove('visible');
            }
        }
    }

    if (backToTop) {
        backToTop.addEventListener('click', (e) => {
            e.preventDefault();
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });
    }

    function copyToClipboard(text, button) {
        navigator.clipboard.writeText(text).then(() => {
            const originalHTML = button.innerHTML;
            button.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M20 6L9 17L4 12" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
            button.style.color = '#4ade80';

            setTimeout(() => {
                button.innerHTML = originalHTML;
                button.style.color = '';
            }, 2000);
        }).catch(err => {
            console.error('Failed to copy:', err);
        });
    }

    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const text = this.getAttribute('data-copy');
            if (text) {
                copyToClipboard(text, this);
            }
        });
    });

    document.querySelectorAll('.code-copy-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const text = this.getAttribute('data-copy');
            if (text) {
                copyToClipboard(text, this);
            }
        });
    });

    let ticking = false;

    function onScroll() {
        if (!ticking) {
            requestAnimationFrame(() => {
                checkStats();
                updateBackToTop();
                ticking = false;
            });
            ticking = true;
        }
    }

    window.addEventListener('scroll', onScroll, { passive: true });

    checkStats();
    updateBackToTop();

    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -100px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);

    document.querySelectorAll('.feature-card, .tool-card, .stat-box, .install-card').forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(30px)';
        el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        observer.observe(el);
    });

})();
