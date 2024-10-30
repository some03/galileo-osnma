use std::f64::consts::PI;

/// 地球の重力定数（m^3/s^2）
const MU: f64 = 3.986004418e14;

/// 平均近点離角Mと離心近点離角Eの関係を解く
/// e: 軌道の離心率
/// M: 平均近点離角（ラジアン）
/// 収束した離心近点離角Eを返します。
fn solve_kepler(e: f64, m: f64) -> f64 {
    let mut e_new = m;
    let mut e_old;
    let tolerance = 1e-12;
    loop {
        e_old = e_new;
        e_new = e_old - (e_old - e * e_old.sin() - m) / (1.0 - e * e_old.cos());
        if (e_new - e_old).abs() < tolerance {
            break;
        }
    }
    e_new
}

/// 真近点離角を求める
/// e: 離心率
/// E: 離心近点離角（ラジアン）
/// 真近点離角vを返します。
fn true_anomaly(e: f64, e_anomaly: f64) -> f64 {
    2.0 * ((1.0 + e).sqrt() * (e_anomaly / 2.0).tan().atan2((1.0 - e).sqrt())).atan()
}

/// 衛星の位置を計算する
/// A: 長半径
/// e: 離心率
/// M0: 平均近点離角の初期値（ラジアン）
/// delta_n: 平均運動の補正（ラジアン/秒）
/// t_k: 経過時間（秒）
/// omega: 近点引数（ラジアン）
/// i0: 初期傾斜角（ラジアン）
/// omega0: 昇交点経度の初期値（ラジアン）
/// omega_dot: 昇交点経度の変化率（ラジアン/秒）
/// cuc, cus: 緯度引数の補正係数
/// crc, crs: 半径の補正係数
/// cic, cis: 傾斜角の補正係数
/// 返り値は (x, y, z) 座標です（メートル）。
fn calculate_position(
    a: f64,
    e: f64,
    m0: f64,
    delta_n: f64,
    t_k: f64,
    omega: f64,
    i0: f64,
    omega0: f64,
    omega_dot: f64,
    cuc: f64true_,
    cus: f64,
    crc: f64,
    crs: f64,
    cic: f64,
    cis: f64,
) -> (f64, f64, f64) {
    // 平均運動 n を計算
    let n0 = (MU / (a * a * a)).sqrt();
    let n = n0 + delta_n;

    // 平均近点離角 M を計算
    let m = m0 + n * t_k;

    // 離心近点離角 E をニュートン-ラフソン法で解く
    let e_anomaly = solve_kepler(e, m);

    // 真近点離角 v を計算
    let v = true_anomaly(e, e_anomaly);

    // 軌道半径 r と修正緯度 u を計算
    let r = a * (1.0 - e * e_anomaly.cos());
    let phi = v + omega;

    // 補正を適用
    let delta_u = cus * (2.0 * phi).sin() + cuc * (2.0 * phi).cos();
    let delta_r = crs * (2.0 * phi).sin() + crc * (2.0 * phi).cos();
    let delta_i = cis * (2.0 * phi).sin() + cic * (2.0 * phi).cos();

    // 補正後の値を計算
    let u = phi + delta_u;
    let r_corrected = r + delta_r;
    let i = i0 + delta_i;

    // 軌道面上の位置を計算
    let x_prime = r_corrected * u.cos();
    let y_prime = r_corrected * u.sin();

    // 昇交点経度 Ω を計算
    let omega_k = omega0 + (omega_dot - 7.2921151467e-5) * t_k; // 7.2921151467e-5 は地球の自転角速度

    // ECEF座標系での位置を計算
    let x = x_prime * omega_k.cos() - y_prime * omega_k.sin() * i.cos();
    let y = x_prime * omega_k.sin() + y_prime * omega_k.cos() * i.cos();
    let z = y_prime * i.sin();

    (x, y, z)
}

fn main() {
    // サンプルのエフェメリスデータ
    let a = 26560_000.0; // 長半径 (m)
    let e = 0.01; // 離心率
    let m0 = 0.1; // 初期の平均近点離角 (rad)
    let delta_n = 4.84813681109536e-9; // 平均運動の補正 (rad/s)
    let t_k = 3600.0; // 経過時間 (s)
    let omega = 1.0; // 近点引数 (rad)
    let i0 = 0.9; // 初期傾斜角 (rad)
    let omega0 = 0.5; // 初期の昇交点経度 (rad)
    let omega_dot = -2.66e-9; // 昇交点経度の変化率 (rad/s)
    let cuc = 1e-6; // 緯度引数の補正係数
    let cus = 2e-6; // 緯度引数の補正係数
    let crc = 1e3; // 半径の補正係数 (m)
    let crs = 1e3; // 半径の補正係数 (m)
    let cic = 1e-6; // 傾斜角の補正係数
    let cis = 2e-6; // 傾斜角の補正係数

    // 衛星の位置を計算
    let (x, y, z) = calculate_position(
        a, e, m0, delta_n, t_k, omega, i0, omega0, omega_dot, cuc, cus, crc, crs, cic, cis,
    );

    println!("衛星の位置 (ECEF): x = {:.2} m, y = {:.2} m, z = {:.2} m", x, y, z);
}
