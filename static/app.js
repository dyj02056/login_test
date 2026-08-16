// 인라인 스크립트와 인라인 스타일을 쓰지 않기 위한 최소한의 동작 모음.
// Content-Security-Policy 를 'unsafe-inline' 없이 유지하려면 이 파일이 필요합니다.

document.addEventListener("DOMContentLoaded", function () {
    // data-confirm 이 붙은 폼은 제출 전에 확인창을 띄운다.
    document.querySelectorAll("form[data-confirm]").forEach(function (form) {
        form.addEventListener("submit", function (event) {
            if (!window.confirm(form.dataset.confirm)) {
                event.preventDefault();
            }
        });
    });

    // 통계 그래프 막대 높이. style 속성 대신 data-height 로 받아 여기서 적용한다.
    document.querySelectorAll(".bar[data-height]").forEach(function (bar) {
        bar.style.height = bar.dataset.height + "%";
    });
});
