(function () {

    const canvas = document.getElementById("particles");
    const ctx = canvas.getContext("2d");
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
            vx: (Math.random() - 0.5) * 0.5,
            vy: (Math.random() - 0.5) * 0.5,
            radius: Math.random() * 2 + 1,
            opacity: Math.random() * 0.5 + 0.2
        };
    }

    function initParticles() {
        particles = [];
        const count = Math.floor((canvas.width * canvas.height) / 15000);
        for (let i = 0; i < count; i++) {
            particles.push(createParticle());
        }
    }

    function updateParticles() {
        particles.forEach(function (p) {
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
        ctx.fillStyle = "#3794ff";

        particles.forEach(function (p) {
            ctx.globalAlpha = p.opacity;
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
            ctx.fill();
        });

        ctx.globalAlpha = 0.1;
        particles.forEach(function (p, i) {
            for (let j = i + 1; j < particles.length; j++) {
                const p2 = particles[j];
                const dx = p.x - p2.x;
                const dy = p.y - p2.y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < 120) {
                    ctx.strokeStyle = "#3794ff";
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

    window.addEventListener("resize", function () {
        resizeCanvas();
        initParticles();
    });

    const revealEls = document.querySelectorAll(".reveal");
    const header = document.querySelector(".header");
    const backTop = document.getElementById("back-top");
    const headerHeight = 60;
    let lastScroll = 0;
    let ticking = false;

    function reveal() {
        const viewH = window.innerHeight;
        const revealTop = viewH * 0.82;

        revealEls.forEach(function (el, i) {
            const rect = el.getBoundingClientRect();
            const delay = Math.min(i * 0.06, 0.35);
            if (rect.top < revealTop) {
                el.style.transitionDelay = delay + "s";
                el.classList.add("revealed");
            }
        });
    }

    function onScroll() {
        lastScroll = window.scrollY;
        if (!ticking) {
            requestAnimationFrame(function () {
                if (lastScroll > 80) {
                    header.style.transform = lastScroll > 120 ? "translateY(-100%)" : "translateY(0)";
                } else {
                    header.style.transform = "translateY(0)";
                }
                if (backTop) {
                    if (lastScroll > 400) {
                        backTop.classList.add("visible");
                    } else {
                        backTop.classList.remove("visible");
                    }
                }
                reveal();
                ticking = false;
            });
            ticking = true;
        }
    }

    document.querySelectorAll('a[href^="#"]').forEach(function (a) {
        a.addEventListener("click", function (e) {
            const id = this.getAttribute("href");
            if (id === "#") return;
            const target = document.querySelector(id);
            if (target) {
                e.preventDefault();
                const top = target.getBoundingClientRect().top + window.scrollY - headerHeight;
                window.scrollTo({ top: top, behavior: "smooth" });
            }
        });
    });

    var installText = "git clone https://github.com/Tosa5656/asmu\ncd asmu\nmake\nmake check\nmake doc\nsudo make install";

    function copyInstall() {
        navigator.clipboard.writeText(installText).then(function () {
            var btn = document.getElementById("install-copy");
            if (btn) {
                btn.textContent = "Скопировано";
                btn.classList.add("copied");
                setTimeout(function () {
                    btn.textContent = "Копировать";
                    btn.classList.remove("copied");
                }, 2000);
            }
        });
    }

    function copyFromCard(btn) {
        var wrap = btn.closest(".code-wrap");
        if (!wrap) return;
        var code = wrap.querySelector("[data-copy]");
        var text = code ? code.getAttribute("data-copy") : code.textContent.trim();
        if (!text) return;
        navigator.clipboard.writeText(text).then(function () {
            btn.textContent = "Скопировано";
            btn.classList.add("copied");
            setTimeout(function () {
                btn.textContent = "Копировать";
                btn.classList.remove("copied");
            }, 2000);
        });
    }

    var installCopyBtn = document.getElementById("install-copy");
    if (installCopyBtn) {
        installCopyBtn.addEventListener("click", copyInstall);
    }

    document.querySelectorAll(".code-wrap .copy-btn").forEach(function (btn) {
        btn.addEventListener("click", function () {
            copyFromCard(this);
        });
    });

    if (backTop) {
        backTop.addEventListener("click", function (e) {
            e.preventDefault();
            window.scrollTo({ top: 0, behavior: "smooth" });
        });
    }

    function animateNumber(el) {
        const target = parseInt(el.getAttribute("data-target"));
        const duration = 2000;
        const start = Date.now();
        const startVal = 0;

        function update() {
            const now = Date.now();
            const elapsed = now - start;
            const progress = Math.min(elapsed / duration, 1);
            const easeOut = 1 - Math.pow(1 - progress, 3);
            const current = Math.floor(startVal + (target - startVal) * easeOut);
            el.textContent = current;

            if (progress < 1) {
                requestAnimationFrame(update);
            } else {
                el.textContent = target;
            }
        }

        update();
    }

    const statNumbers = document.querySelectorAll(".stat-number");
    let statsAnimated = false;

    function checkStats() {
        if (statsAnimated) return;
        const hero = document.querySelector(".hero");
        if (!hero) return;

        const rect = hero.getBoundingClientRect();
        if (rect.top < window.innerHeight && rect.bottom > 0) {
            statNumbers.forEach(function (el) {
                animateNumber(el);
            });
            statsAnimated = true;
        }
    }

    const cards = document.querySelectorAll("[data-tilt]");

    cards.forEach(function (card) {
        card.addEventListener("mousemove", function (e) {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            const centerX = rect.width / 2;
            const centerY = rect.height / 2;
            const rotateX = (y - centerY) / 10;
            const rotateY = (centerX - x) / 10;

            card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-6px) scale(1.02)`;
        });

        card.addEventListener("mouseleave", function () {
            card.style.transform = "";
        });
    });

    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("scroll", checkStats, { passive: true });
    window.addEventListener("resize", reveal);
    reveal();
    onScroll();
    checkStats();
})();
