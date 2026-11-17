// 画面の描画の前にテーマを決める（ちらつきを防ぐ）. CSP で inline のスクリプトを許さないため、別のファイルにしている.
try { var t = localStorage.getItem('sruru.theme'); if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t) } catch (e) {}
