def calc_new_weight (t : i64) (eta : f64) (beta1 : f64) (beta2 : f64) (epsilon : f64) (old_m_dw : f64) (old_v_dw : f64) (dw : f64) (w : f64) =
  let m_dw = beta1 * old_m_dw + (1f64 - beta1) * dw
  let v_dw = beta2*old_v_dw + (1f64 - beta2)*(dw**2)
  let m_dw_corr = m_dw / (1 - beta1**(f64.i64 t))
  let v_dw_corr = v_dw / (1 - beta2**(f64.i64 t))
  let new_w = w - eta*(m_dw_corr / ((f64.sqrt v_dw_corr) + epsilon))
  in (new_w, m_dw, v_dw)

def adam_conv [o][l][p][k] (t : i64) (eta : f64) (beta1 : f64) (beta2 : f64) (epsilon : f64) (weights) (weights_grad) (cache) =
  let (m_dw, m_db, v_dw, v_db) : ([o][l][p][k]f64,[o]f64,[o][l][p][k]f64,[o]f64) = cache
  let (w, b) : ([o][l][p][k]f64,[o]f64) = weights
  let (dw, db) : ([o][l][p][k]f64,[o]f64) = weights_grad

  let res_w_4d = map4 (map4 (map4 (map4 (\ a b c d -> calc_new_weight t eta beta1 beta2 epsilon a b c d)))) m_dw v_dw dw w
  let (new_b, m_db, v_db) = unzip3 (map4 (\ a b c d -> calc_new_weight t eta beta1 beta2 epsilon a b c d) m_db v_db db b)
  let new_w = map (map (map (map (\ x -> x.0)))) res_w_4d
  let m_dw = map (map (map (map (\ x -> x.1)))) res_w_4d
  let v_dw = map (map (map (map (\ x -> x.2)))) res_w_4d
  in (new_w,new_b,(m_dw, m_db, v_dw, v_db))

def adam_dense [m][n] (t : i64) (eta : f64) (beta1 : f64) (beta2 : f64) (epsilon : f64) (weights) (weights_grad) (cache) =
  let (m_dw, m_db, v_dw, v_db) : ([m][n]f64,[m]f64,[m][n]f64,[m]f64) = cache
  let (w, b) : ([m][n]f64,[m]f64) = weights
  let (dw, db) : ([m][n]f64,[m]f64) = weights_grad

  let (new_w, m_dw, v_dw) = unzip3 (map unzip3 ((map4 (map4 (\ a b c d -> calc_new_weight t eta beta1 beta2 epsilon a b c d)) m_dw v_dw dw w)))
  let (new_b, m_db, v_db) = unzip3 (map4 (\ a b c d -> calc_new_weight t eta beta1 beta2 epsilon a b c d) m_db v_db db b)
  in (new_w,new_b,(m_dw, m_db, v_dw, v_db))

def adam_block (t : i64) (eta : f64) (beta1 : f64) (beta2 : f64) (epsilon : f64) (weights) (weights_grad) (cache) =
  let (c1_w,c1_b,t_w,t_b,c2_w,c2_b) = weights
  let (c1_w_grad, c1_b_grad, t_w_grad, t_b_grad, c2_w_grad, c2_b_grad) = weights_grad
  let (c1_cache,t_cache,c2_cache) = cache
  let (new_c1_w,new_c1_b,c1_cache) = adam_conv t eta beta1 beta2 epsilon (c1_w, c1_b) (c1_w_grad, c1_b_grad) c1_cache
  let (new_t_w,new_t_b,t_cache) = adam_dense t eta beta1 beta2 epsilon (t_w, t_b) (t_w_grad, t_b_grad) t_cache
  let (new_c2_w,new_c2_b,c2_cache) = adam_conv t eta beta1 beta2 epsilon (c2_w, c2_b) (c2_w_grad, c2_b_grad) c2_cache

  in ((new_c1_w,new_c1_b,new_t_w,new_t_b,new_c2_w,new_c2_b),(c1_cache,t_cache,c2_cache))

def adam_unet (t : i64) (eta : f64) (beta1 : f64) (beta2 : f64) (epsilon : f64) (weights) (weights_grad) (cache) =
  let (c_in_cache, bd1_cache, bd2_cache, bu2_cache, bu1_cache, c_out_cache) = cache
  let (c_in_grad,bd1_grad,bd2_grad,bu2_grad,bu1_grad,c_out_grad) = weights_grad
  let (c_in_w,bd1_w,bd2_w,bu2_w,bu1_w,c_out_w) = weights
  let (new_c_in_w, new_c_in_b,c_in_cache) = adam_conv t eta beta1 beta2 epsilon c_in_w c_in_grad c_in_cache
  let (new_bd1_w,bd1_cache) = adam_block t eta beta1 beta2 epsilon bd1_w bd1_grad bd1_cache
  let (new_bd2_w,bd2_cache) = adam_block t eta beta1 beta2 epsilon bd2_w bd2_grad bd2_cache
  let (new_bu2_w,bu2_cache) = adam_block t eta beta1 beta2 epsilon bu2_w bu2_grad bu2_cache
  let (new_bu1_w,bu1_cache) = adam_block t eta beta1 beta2 epsilon bu1_w bu1_grad bu1_cache
  let (new_c_out_w,new_c_out_b,c_out_cache) = adam_conv t eta beta1 beta2 epsilon c_out_w c_out_grad c_out_cache

  let new_c_in_ws = (new_c_in_w,new_c_in_b)
  let new_c_out_ws = (new_c_out_w,new_c_out_b)

  in ((new_c_in_ws,new_bd1_w,new_bd2_w,new_bu2_w,new_bu1_w,new_c_out_ws),(c_in_cache, bd1_cache, bd2_cache, bu2_cache, bu1_cache, c_out_cache))

def mk_initial_adam () =
  let a_Cin_w : [64][1][3][3]f64 = replicate 64 (replicate 1 (replicate 3 (replicate 3 0f64)))
  let a_Cin_b : [64]f64 = replicate 64 0f64
  let a_Cin_w1 : [64][1][3][3]f64 = replicate 64 (replicate 1 (replicate 3 (replicate 3 0f64)))
  let a_Cin_b1 : [64]f64 = replicate 64 0f64

  let a_bd1_w1 : [128][64][3][3]f64 = replicate 128 (replicate 64 (replicate 3 (replicate 3 0f64)))
  let a_bd1_b1 : [128]f64 = replicate 128 0f64
  let a_bd1_w2 : [128][128][3][3]f64 = replicate 128 (replicate 128 (replicate 3 (replicate 3 0f64)))
  let a_bd1_b2 : [128]f64 = replicate 128 0f64
  let a_bd1_tw : [128][256]f64 = replicate 128 (replicate 256 0f64)
  let a_bd1_tb : [128]f64 = replicate 128 0f64

  let a_bd2_w1 : [256][128][3][3]f64 = replicate 256 (replicate 128 (replicate 3 (replicate 3 0f64)))
  let a_bd2_b1 : [256]f64 = replicate 256 0f64
  let a_bd2_w2 : [256][256][3][3]f64 = replicate 256 (replicate 256 (replicate 3 (replicate 3 0f64)))
  let a_bd2_b2 : [256]f64 = replicate 256 0f64
  let a_bd2_tw : [256][256]f64 = replicate 256 (replicate 256 0f64)
  let a_bd2_tb : [256]f64 = replicate 256 0f64

  let a_bu2_w1 : [128][512][3][3]f64 = replicate 128 (replicate 512 (replicate 3 (replicate 3 0f64)))
  let a_bu2_b1 : [128]f64 = replicate 128 0f64
  let a_bu2_w2 : [128][128][3][3]f64 = replicate 128 (replicate 128 (replicate 3 (replicate 3 0f64)))
  let a_bu2_b2 : [128]f64 = replicate 128 0f64
  let a_bu2_tw : [128][256]f64 = replicate 128 (replicate 256 0f64)
  let a_bu2_tb : [128]f64 = replicate 128 0f64

  let a_bu1_w1 : [64][256][3][3]f64 = replicate 64 (replicate 256 (replicate 3 (replicate 3 0f64)))
  let a_bu1_b1 : [64]f64 = replicate 64 0f64
  let a_bu1_w2 : [64][64][3][3]f64 = replicate 64 (replicate 64 (replicate 3 (replicate 3 0f64)))
  let a_bu1_b2 : [64]f64 = replicate 64 0f64
  let a_bu1_tw : [64][256]f64 = replicate 64 (replicate 256 0f64)
  let a_bu1_tb : [64]f64 = replicate 64 0f64

  let a_Cout_w : [1][64][1][1]f64 = [replicate 64 (replicate 1 (replicate 1 0f64))]
  let a_Cout_b : [1]f64 = replicate 1 0f64

  let a_C_in = (a_Cin_w,a_Cin_b,a_Cin_w1,a_Cin_b1)
  let a_bd1_w = ((a_bd1_w1,a_bd1_b1,a_bd1_w1,a_bd1_b1),(a_bd1_tw,a_bd1_tb,a_bd1_tw,a_bd1_tb),(a_bd1_w2,a_bd1_b2,a_bd1_w2,a_bd1_b2))
  let a_bd2_w = ((a_bd2_w1,a_bd2_b1,a_bd2_w1,a_bd2_b1),(a_bd2_tw,a_bd2_tb,a_bd2_tw,a_bd2_tb),(a_bd2_w2,a_bd2_b2,a_bd2_w2,a_bd2_b2))
  let a_bu2_w = ((a_bu2_w1,a_bu2_b1,a_bu2_w1,a_bu2_b1),(a_bu2_tw,a_bu2_tb,a_bu2_tw,a_bu2_tb),(a_bu2_w2,a_bu2_b2,a_bu2_w2,a_bu2_b2))
  let a_bu1_w = ((a_bu1_w1,a_bu1_b1,a_bu1_w1,a_bu1_b1),(a_bu1_tw,a_bu1_tb,a_bu1_tw,a_bu1_tb),(a_bu1_w2,a_bu1_b2,a_bu1_w2,a_bu1_b2))
  let a_C_out = (a_Cout_w,a_Cout_b,a_Cout_w,a_Cout_b)

  in (a_C_in,a_bd1_w,a_bd2_w,a_bu2_w,a_bu1_w,a_C_out)


-- SGD
def SGD (w : f64) (g : f64) : f64 =
  w - 0.1*g

def lenet_SGD (gradients) (weights) =
  let (C1_w,C1_b,C3_w,C3_b,F6_w,F6_b,F7_w,F7_b,F8_w,F8_b) = weights
  let (C1_w_grad,C1_b_grad,C3_w_grad,C3_b_grad,F6_w_grad,F6_b_grad,F7_w_grad,F7_b_grad,F8_w_grad,F8_b_grad) = gradients
  in (map2 (map2 (map2 (map2 SGD))) C1_w C1_w_grad,
    map2 SGD C1_b C1_b_grad,
    map2 (map2 (map2 (map2 SGD))) C3_w C3_w_grad,
    map2 SGD C3_b C3_b_grad,
    map2 (map2 SGD) F6_w F6_w_grad,
    map2 SGD F6_b F6_b_grad,
    map2 (map2 SGD) F7_w F7_w_grad,
    map2 SGD F7_b F7_b_grad,
    map2 (map2 SGD) F8_w F8_w_grad,
    map2 SGD F8_b F8_b_grad)