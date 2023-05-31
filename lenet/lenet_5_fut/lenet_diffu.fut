import "lib/github.com/diku-dk/cpprandom/random"
module rng_engine = minstd_rand
module rand_f64 = normal_distribution f64 rng_engine
module rand_i64_uniform = uniform_int_distribution i64 rng_engine

def sinusoidal_position_embeddings (dim : f64) (t : f64) =
  let half_dim = f64.floor (dim / 2)
  --let out_dim = i64.f64 half_dim*2
  let emb = (f64.log 10000) / (half_dim-1)
  let emb_arr = tabulate (i64.f64 half_dim) (\ i -> f64.exp((f64.i64 i)*(-emb)))
  let emb_arr_2d = map (\ e -> e*t) emb_arr
  let emb_sin = map (\ x -> f64.sin x) emb_arr_2d
  let emb_cos = map (\ x -> f64.cos x) emb_arr_2d
  in emb_sin ++ emb_cos

def mk_rand_seeds (seed : i32) (n : i64) : [n]i32 =
  let rng_state = rng_engine.rng_from_seed [seed]
  let rng_states = rng_engine.split_rng (n) rng_state
  let rng_numb = (unzip (map (rand_i64_uniform.rand (0,9999)) rng_states)).1
  in map i32.i64 rng_numb

def mk_rand_int (seed : i32) (min_val : i64) (max_val : i64) : i64 =
  let rng_state = rng_engine.rng_from_seed [seed]
  let (_,x) = rand_i64_uniform.rand (min_val,max_val) rng_state
  in x

def mk_rand_ints (seed : i32) (n : i64) (m : i64) (min_val : i64) (max_val : i64) : [n][m]i32 =
  let rng_state = rng_engine.rng_from_seed [seed]
  let rng_states = rng_engine.split_rng (n*m) rng_state
  let rng_numb = (unzip (map (rand_i64_uniform.rand (min_val,max_val)) rng_states)).1
  let rng_i32 = map i32.i64 rng_numb
  in unflatten n m rng_i32

def add_padding [l][n][m] (imgs : [l][n][m]f64) (padding : i64) =
  let n_pad = (n+(padding*2))
  let m_pad = (m+(padding*2))
  in map (\ img_i -> tabulate_2d n_pad m_pad (\ i j ->
      if (i >= padding && i < (n+padding) && j >= padding && j < (m+padding)) then img_i[i-padding,j-padding] else 0)) imgs

def ReLU (x : f64) =
  f64.max 0f64 x

def ReLU_b (x : f64) =
  if x > 0f64 then 1f64 else 0f64


def sigmoid (x : f64) =
  1/(1 + f64.exp (-x))

def sigmoid_b (out_grad : f64) (input : f64 ) =
  let s = sigmoid input
  in out_grad * (s * (1f64-s))

def convolve2D_test [n][m][p][k][l][o] (imgs : [l][n][m]f64) (kernels : [o][l][p][k]f64) (biases : [o][][]f64) (padding : i64) =
  let flat_pk = p*k
  let new_n = (((n+(padding*2))-p)+1)
  let new_m = (((m+(padding*2))-p)+1)

  let imgs_padded =
    if (padding != 0) then
      add_padding imgs padding
    else
      imgs

  let c1 = map (\ kernel_3d ->
    tabulate_2d new_n new_m (\ y x ->
      reduce (+) 0 (flatten (map2 (\ kernel img ->
        (flatten (map2 (\ i j ->
          map2 (*) i j)
        (img[y:(y+p),x:(x+k)] :> [p][k]f64) kernel)) :> [flat_pk]f64
      ) kernel_3d imgs_padded))
    )
  ) kernels

  let c1_b = map2 (\ y x -> map2 (\ r_c r_b -> map2 (+) r_c r_b) y x) c1 (biases :> [o][new_n][new_m]f64)
  in c1_b



def convolve2D_simple [n][m][p][k] (img : [n][m]f64) (kernel : [p][k]f64) (padding : i64) =
  --let flat_pk = p*k
  let new_n = (((n+(padding*2))-p)+1)
  let new_m = (((m+(padding*2))-p)+1)

  let img_padded =
    if (padding != 0) then
      flatten (add_padding [img] padding)
    else
      img

  let c1 =
    tabulate_2d new_n new_m (\ y x ->
      reduce (+) 0
        (flatten (map2 (\ i j ->
          map2 (*) i j)
        (img_padded[y:(y+p),x:(x+k)] :> [p][k]f64) kernel))
    )
  in c1

def matadd [m][n] (xss : [m][n]f64) (yss : [m][n]f64) : [m][n]f64 =
  map2 (\ xs ys -> map2 (+) xs ys) xss yss

def convolve2D_b [n][m][p][k][l][o][q][r] (out_grad : [o][q][r]f64) (conv_input : [l][n][m]f64) (kernels : [o][l][p][k]f64) (biases : [o]f64) (learning_rate : f64) (full_num : i64) =
  let out_grad_ReLU_b = map (\ z -> map (\y -> map ReLU_b y) z ) out_grad
  let kernels_grad : [o][l][p][k]f64 = tabulate_2d o l (\ y x -> convolve2D_simple conv_input[x] out_grad_ReLU_b[y] 0 :> [p][k]f64)
  let input_grad_split = tabulate_2d o l (\ y x -> convolve2D_simple out_grad_ReLU_b[y] kernels[y,x] full_num :> [n][m]f64)
  let zeros = tabulate_2d n m (\ _ _ -> 0f64)
  let input_grad = map (\ x -> foldr matadd zeros x) (transpose input_grad_split)
  let new_kernels = map2 (\ kern_3d kern_grad_3d -> map2 (\ kern_2d kern_grad_2d -> map2 (\ kern_1d kern_grad_1d -> map2 (\ k k_g -> k - (learning_rate * k_g)) kern_1d kern_grad_1d) kern_2d kern_grad_2d) kern_3d kern_grad_3d) kernels kernels_grad
  let dl_db = map (\ o_g -> reduce (+) 0 (flatten o_g)) out_grad_ReLU_b
  let new_biases = map2 (\ d_b b -> b - (learning_rate * d_b)) dl_db biases
  in (input_grad, new_kernels, new_biases)

def convolve2D_b_test [n][m][p][k][l][o][q][r] (out_grad : [o][q][r]f64) (conv_input : [l][n][m]f64) (kernels : [o][l][p][k]f64) (biases : [o][][]f64)  (learning_rate : f64) (valid_num : i64) (full_num : i64) =
  let kernels_grad : [o][l][p][k]f64 = tabulate_2d o l (\ y x -> convolve2D_simple conv_input[x] out_grad[y] valid_num :> [p][k]f64)
  let input_grad_split = tabulate_2d o l (\ y x -> convolve2D_simple out_grad[y] kernels[y,x] full_num :> [n][m]f64)
  let zeros = tabulate_2d n m (\ _ _ -> 0f64)
  let input_grad = map (\ x -> foldr matadd zeros x) (transpose input_grad_split)
  let new_kernels = map2 (\ kern_3d kern_grad_3d -> map2 (\ kern_2d kern_grad_2d -> map2 (\ kern_1d kern_grad_1d -> map2 (\ k k_g -> k - (learning_rate * k_g)) kern_1d kern_grad_1d) kern_2d kern_grad_2d) kern_3d kern_grad_3d) kernels kernels_grad
  let new_biases = map2 (\ y x -> map2 (\ y_r x_r -> map2 (\ ogb nbs -> nbs - (learning_rate * ogb)) y_r x_r ) y x) out_grad biases
  in (input_grad, new_kernels, new_biases)


def dotprod [n] (xs: [n]f64) (ys: [n]f64) : f64 =
  reduce (+) 0f64 (map2 (*) xs ys)

let matmul [n][p][m] (xss: [n][p]f64) (yss: [p][m]f64): [n][m]f64 =
    map (\xs -> map (dotprod xs) (transpose yss)) xss

let matmul_scalar [m][n] (xss: [m][n]f32) (k: f32): *[m][n]f32 =
  map (map (*k)) xss

def dense_activation [m][n] (input : [n]f64) (ws : [m][n]f64) (bs : [m]f64) : [m]f64 =
    map2 (\ w b -> ReLU((dotprod input w) + b)) ws bs


def dense_activation_b [m][n] (out_grad : [m]f64) (dense_input : [n]f64) (ws : [m][n]f64) (bs : [m]f64) (learning_rate : f64) =
  let out_grad_ReLU_b = map ReLU_b out_grad
  let ws_g = map (\ x -> map (\ y -> y*x) dense_input) out_grad_ReLU_b
  let input_g = matmul (transpose ws) (transpose [out_grad_ReLU_b])
  let new_ws = map2 (\ w_r wg_r -> map2 (\ w wg -> w - (learning_rate * wg)) w_r wg_r) ws ws_g
  let new_bs = map2 (\ b o_g -> b - (learning_rate*o_g)) bs out_grad_ReLU_b
  in (input_g, new_ws, new_bs)

def dense [m][n] (input : [n]f64) (ws : [m][n]f64) (bs : [m]f64) : [m]f64 =
    map2 (\ w b -> (dotprod input w) + b) ws bs

def dense_b [m][n] (out_grad : [m]f64) (dense_input : [n]f64) (ws : [m][n]f64) (bs : [m]f64) (learning_rate : f64) : ([n][1]f64, [m][n]f64, [m]f64) =
  let ws_g :[m][n]f64 = map (\ x -> map (\ y -> y*x) dense_input) out_grad
  let input_g = matmul (transpose ws) (transpose [out_grad])
  let new_ws = map2 (\ w_r wg_r -> map2 (\ w wg -> w - (learning_rate * wg)) w_r wg_r) ws ws_g
  let new_bs = map2 (\ b o_g -> b - (learning_rate*o_g)) bs out_grad
  in (input_g, new_ws, new_bs)


def convolve2D [n][m][p][k][l][o][t] (imgs : [l][n][m]f64) (kernels : [o][l][p][k]f64) (biases : [o][][]f64) (padding : i64) (time_mlp : [t]f64) (t_weights : [o][t]f64) (t_bias : [o]f64) =
  let flat_pk = p*k
  let new_n = (((n+(padding*2))-p)+1)
  let new_m = (((m+(padding*2))-p)+1)

  let imgs_padded =
    if (padding != 0) then
      add_padding imgs padding
    else
      imgs

  let c1 = map (\ kernel_3d ->
    tabulate_2d new_n new_m (\ y x ->
      reduce (+) 0 (flatten (map2 (\ kernel img ->
        (flatten (map2 (\ i j ->
          map2 (*) i j)
        (img[y:(y+p),x:(x+k)] :> [p][k]f64) kernel)) :> [flat_pk]f64
      ) kernel_3d imgs_padded))
    )
  ) kernels

  let c1_b = map2 (\ y x -> map2 (\ r_c r_b -> map2 (+) r_c r_b) y x) c1 (biases :> [o][new_n][new_m]f64)

  let time_mlp_ = dense time_mlp t_weights t_bias

  let res = tabulate_3d o new_n new_m (\ z y x -> c1_b[z,y,x] + time_mlp_[z])

  in res


def time_embedding_layer [l][n][m][t] (imgs : [l][n][m]f64) (time_mlp : [t]f64) (t_weights : [l][t]f64) (t_bias : [l]f64) =
    let time_emb = dense_activation time_mlp t_weights t_bias
    in tabulate_3d l n m (\ z y x -> imgs[z,y,x] + time_emb[z])

def time_embedding_layer_b [l][n][m][t] (out_grad : [l][n][m]f64) (time_mlp_in : [t]f64) (t_weights : [l][t]f64) (t_bias : [l]f64) (learning_rate : f64) =
  let time_emb_grad = map (\ t_g -> reduce (+) 0 (flatten t_g)) out_grad
  let (time_grad, new_t_ws, new_t_bs) = dense_activation_b time_emb_grad time_mlp_in t_weights t_bias learning_rate
  let time_grad_flat = flatten time_grad
  let input_g = tabulate_3d l n m (\ z y x ->  out_grad[z,y,x] + time_grad_flat[z])
  in (input_g, new_t_ws, new_t_bs)


--def max_pool [l][n][m] (img : [l][n][m]f64) (stride : i64) =
 -- tabulate_2d (n/stride) (m/stride) (\ y x -> f64.maximum (flatten img[(y*stride):(y*stride)+stride, (x*stride):(x*stride)+stride]))

def avg_pool [l][n][m] (imgs : [l][n][m]f64) (stride : i64) =
  let out_y = (n/stride)
  let out_x = (m/stride)
  in map (\img -> (tabulate_2d (n/stride) (m/stride) (\ y x -> (reduce (+) 0 (flatten img[(y*stride):(y*stride)+stride, (x*stride):(x*stride)+stride])) / f64.i64 (stride*stride))) :> [out_y][out_x]f64) imgs

def avg_pool_b [l][n][m] (imgs : [l][n][m]f64) (stride : i64) =
  let out_y = (n*stride)
  let out_x = (m*stride)
  in map (\img -> (tabulate_2d out_y out_x (\ y x -> img[y/stride, x/stride] / f64.i64 (stride*stride)) ) ) imgs

def mk_rand_array (seed : i32) (n : i64) (m : i64) : [n][m]f64 =
  let rng_state = rng_engine.rng_from_seed [seed]
  let rng_states = rng_engine.split_rng (n*m) rng_state
  let rng_numb = (unzip (map (rand_f64.rand {mean = 0, stddev = 1}) rng_states)).1
  in unflatten n m rng_numb



--softmax_b [1f64,2f64,3f64,4f64,5f64] 0f64 [1f64,2f64,3f64,4f64,5f64]

def softmax (X : []f64) =
  let X_exp = map f64.exp X
  let X_sum = f64.sum X_exp
  in map (\ x -> x / X_sum) X_exp


def mse [n] (y_true : [n]f64) (y_pred : [n]f64) =
  (reduce (+) 0 (map2 (\t p -> (t - p)**2) y_true y_pred)) / (f64.i64 n)

def mse_loss_img [n][m] (y_true : [n][m]f64) (y_pred : [n][m]f64) =
  let sum = f64.sum (map2 (\ y x -> mse y x) y_true y_pred)
  in sum / f64.i64 n


def mse_prime [n] (y_true : [n]f64) (y_pred : [n]f64) =
  map2 (\ t p -> 2f64*(p-t) / (f64.i64 n)) y_true y_pred

let mse_loss_img_prime [n][m] (y_true : [n][m]f64) (y_pred : [n][m]f64) : [n][m]f64 =
  map2 (\ y x -> map2 (\ t p -> 2f64*(p-t) / (f64.i64 (n*m))) y x) y_true y_pred

def softmax_b [m] (out_grad : [m]f64) (learning_rate : f64) (softmax_pred : [m]f64) =
  --let learning_rate_2 = learning_rate
  let identity : [m][m]f64 = tabulate_2d m m (\ y x -> if x == y then 1f64 else 0f64)
  let test = map (\ y -> map2 (-) y softmax_pred) identity
  let test2 = map2 (\id pred -> map (\ x -> pred * x) id) test softmax_pred
  let out_grad_2d = map (\x -> [x]) out_grad
  let test3 = matmul test2 out_grad_2d
  in test3

--softmax_b [-0.22,0.73,-0.8,-0.12,0.6] 1 (softmax [0.2,0.3,0.5,0.7,0.6] )

def mk_beta (steps : i64) (start : f64) (stop: f64) : [steps]f64 =
  tabulate steps (\i -> start+(f64.i64 i)*((stop-start)/((f64.i64 steps)-1f64)))

def mk_alpha [n] (betas : [n]f64) : [n]f64 =
  map (\b -> 1f64 - b) betas

def mk_alpha_bar [n] (alphas : [n]f64) : [n]f64 =
  scan (*) 1 alphas

def q_xt_x0 [n][m][l][o] (x0 : [n][m]f64) (t : [l]i64) (alpha_bar : [o]f64) : ([l][n][m]f64,[l]f64) =
  let abar_t = map (\ i -> alpha_bar[i]) t
  let abar_t_pow = map (\ a -> a**0.5f64) abar_t
  let mean = map (\ a -> tabulate_2d n m (\ y x -> x0[y,x] * a)) abar_t_pow
  let var = map (\ a -> 1f64-a) abar_t
  in (mean,var)

def q_sample [n][m][l][o][p][q] (x0 : [n][m]f64) (t : [l]i64) (alpha_bar : [o]f64) (eps : [p][q]f64) =
  let eps : [n][m]f64 = if q == 0i64 then mk_rand_array 42 n m else eps :> [n][m]f64
  let (mean,var) = q_xt_x0 x0 t alpha_bar
  let var_pow = map (\ a -> a**0.5f64) var
  let inter_res = map (\var_ -> tabulate_2d n m (\ y x -> var_*eps[y,x])) var_pow
  in map2 (\ mean_ inter_res_ -> tabulate_2d n m (\ y x -> mean_[y,x] + inter_res_[y,x])) mean inter_res

def testdiffu [t][n][m] (imgs : [t][n][m]f64) (epochs : i64) (learning_rate : f64) (seeds : []i32) (seeds_time : [][]i32) =

  let beta = mk_beta 1000 0.0001 0.02
  let alpha = mk_alpha beta
  let alpha_bar = mk_alpha_bar alpha

  let C1_w : [5][1][3][3]f64 = tabulate 5 (\ i -> [mk_rand_array ((i32.i64 i)+seeds[0]) 3 3])
  let C1_b : [5][26][26]f64 = tabulate 5 (\ i -> mk_rand_array ((i32.i64 i)+seeds[1]) 26 26)
  let C2_w : [6][5][3][3]f64 = tabulate 6 (\ i -> tabulate 5 (\ j -> mk_rand_array ((i32.i64 j)+seeds[2]+seeds[13+i]) 3 3))
  let C2_b : [6][24][24]f64 = tabulate 6 (\ i -> mk_rand_array ((i32.i64 i)+seeds[3]) 24 24)
  let F4_w : [784][3456]f64 = mk_rand_array seeds[4] 784 3456 :> [784][3456]f64
  let F4_b : [784]f64 = flatten (mk_rand_array seeds[5] 1 784) :> [784]f64
  let t_w1 : [5][32]f64 = mk_rand_array seeds[8] 5 32 :> [5][32]f64
  let t_b1 : [5]f64 = flatten (mk_rand_array seeds[9] 1 5) :> [5]f64
  let t_w2 : [6][32]f64 = mk_rand_array seeds[10] 6 32 :> [6][32]f64
  let t_b2 : [6]f64 = flatten (mk_rand_array seeds[11] 1 6) :> [6]f64

  let train_epochs = loop (C1_w,C1_b,C2_w,C2_b,F4_w,F4_b,t_w1,t_b1,t_w2,t_b2,errors,best_loss,best_wandb) = (C1_w,C1_b,C2_w,C2_b,F4_w,F4_b,t_w1,t_b1,t_w2,t_b2,[],f64.highest,[]) for j < epochs do
    let wandb = loop (C1_w,C1_b,C2_w,C2_b,F4_w,F4_b,t_w1,t_b1,t_w2,t_b2,error) = (C1_w,C1_b,C2_w,C2_b,F4_w,F4_b,t_w1,t_b1,t_w2,t_b2,0f64) for i < t do

      let time = mk_rand_int (i32.i64 i) 1 1000
      let noise = mk_rand_array (i32.i64 i) n m
      let xt = q_sample imgs[i] [time] alpha_bar noise
      let t = sinusoidal_position_embeddings 32 (f64.i64 time) :> [32]f64

      let C1_layer : [5][26][26]f64 = convolve2D_test xt C1_w C1_b 0 :> [5][26][26]f64
      let C1_layer_activation : [5][26][26]f64 = map (\ y -> map (\ x -> map sigmoid x) y) C1_layer
      let C1_time_embedding_layer : [5][26][26]f64 = time_embedding_layer C1_layer_activation t t_w1 t_b1
      let C2_layer : [6][24][24]f64 = convolve2D_test C1_time_embedding_layer C2_w C2_b 0 :> [6][24][24]f64
      let C2_layer_activation : [6][24][24]f64 = map (\ y -> map (\ x -> map sigmoid x) y) C2_layer
      let C2_time_embedding_layer : [6][24][24]f64 = time_embedding_layer C2_layer_activation t t_w2 t_b2
      let F3_layer : [3456]f64 = flatten (flatten C2_time_embedding_layer) :> [3456]f64
      let F4_layer : [784]f64 = dense F3_layer F4_w F4_b
      let prediction = softmax F4_layer
      let prediction_2d = unflatten n m prediction
      let error : f64 = error + (mse_loss_img noise prediction_2d)
      let grad_2d = mse_loss_img_prime noise prediction_2d
      let grad = flatten grad_2d :> [784]f64
      let prediction_b : [784]f64 = flatten (softmax_b grad learning_rate prediction) :> [784]f64
      let F4_layer_b = dense_b prediction_b F3_layer F4_w F4_b learning_rate
      let F4_out_grad : [3456]f64 = flatten F4_layer_b.0 :> [3456]f64
      let new_F4_w : [784][3456]f64 = F4_layer_b.1
      let new_F4_b : [784]f64 = F4_layer_b.2
      let F3_layer_b = unflatten_3d 6 24 24 F4_out_grad
      let (C2_time_embedding_layer_b,new_t_w2,new_t_b2) = time_embedding_layer_b F3_layer_b t t_w2 t_b2 learning_rate
      let C2_layer_activation_b = map2 (\ y_g y -> map2 (\ x_g x -> map2 sigmoid_b x_g x) y_g y) C2_time_embedding_layer_b C2_layer
      let C2_layer_b = convolve2D_b_test C2_layer_activation_b C1_layer C2_w C2_b learning_rate 0 2
      let C2_out_grad : [5][26][26]f64 = C2_layer_b.0
      let new_C2_w : [6][5][3][3]f64 = C2_layer_b.1
      let new_C2_b : [6][24][24]f64 = C2_layer_b.2
      let (C1_time_embedding_layer_b,new_t_w1,new_t_b1) = time_embedding_layer_b C2_out_grad t t_w1 t_b1 learning_rate
      let C1_layer_activation_b = map2 (\ y_g y -> map2 (\ x_g x -> map2 sigmoid_b x_g x) y_g y) C1_time_embedding_layer_b C1_layer
      let C1_layer_b = convolve2D_b_test C1_layer_activation_b [imgs[i]] C1_w C1_b learning_rate 0 2
      let C1_out_grad : [1][n][m]f64 = C1_layer_b.0
      let new_C1_w : [5][1][3][3]f64 = C1_layer_b.1
      let new_C1_b : [5][26][26]f64 = C1_layer_b.2
      in (new_C1_w,new_C1_b,new_C2_w,new_C2_b,new_F4_w,new_F4_b,new_t_w1,new_t_b1,new_t_w2,new_t_b2,error)
    let loss = (wandb.10/(f64.i64 t))
    let errors = errors++[loss]
    let best_wandb = if loss < best_loss then [(wandb.0,wandb.1,wandb.2,wandb.3,wandb.4,wandb.5,wandb.6,wandb.7,wandb.8,wandb.9)] else best_wandb
    let best_loss = if loss < best_loss then loss else best_loss
    in (wandb.0,wandb.1,wandb.2,wandb.3,wandb.4,wandb.5,wandb.6,wandb.7,wandb.8,wandb.9,errors,best_loss,best_wandb)
  in (train_epochs.10, train_epochs.11, train_epochs.12)

def pred_diffu [n][m] (wandb) (img : [n][m]f64) (t_in : i64) =
  let (C1_w,C1_b,C3_w,C3_b,t_w1,t_b1,t_w2,t_b2,F5_w,F5_b) = wandb
  let t = sinusoidal_position_embeddings 32 (f64.i64 t_in) :> [32]f64
  let C1_layer : [6][28][28]f64 = convolve2D_test [img] C1_w C1_b 2 :> [6][28][28]f64
  let C1_layer_activation : [6][28][28]f64 = map (\ y -> map (\ x -> map sigmoid x) y) C1_layer
  let C1_time_embedding_layer : [6][28][28]f64 = time_embedding_layer C1_layer_activation t t_w1 t_b1
  let S2_layer : [6][14][14]f64 = avg_pool C1_time_embedding_layer 2 :> [6][14][14]f64
  let C3_layer : [16][10][10]f64 = convolve2D_test S2_layer C3_w C3_b 0 :> [16][10][10]f64
  let C3_layer_activation : [16][10][10]f64 = map (\ y -> map (\ x -> map sigmoid x) y) C3_layer
  let C3_time_embedding_layer : [16][10][10]f64 = time_embedding_layer C3_layer_activation t t_w2 t_b2
  let S4_layer : [16][5][5]f64 = avg_pool C3_time_embedding_layer 2 :> [16][5][5]f64
  let F5_layer : [400]f64 = flatten (flatten S4_layer) :> [400]f64
  let prediction : [784]f64 = dense F5_layer F5_w F5_b
  in unflatten n m prediction




-- task_1
-- ==
-- compiled input @ ./mnist_data_one_1000.in
-- output {20f64}

-- diffusion main
let main (x_train : [][][]f64) (y_train : [][]f64) (x_test : [][][]f64) (y_test : [][]f64) =
  let some_x_train = x_train[:1]
  let some_y_train = y_train[:1]

  let some_x_test = x_test[:1]
  let some_y_test = y_test[:1]

  let seeds = mk_rand_seeds 42 1000

  let C1_w : [6][1][5][5]f64 = tabulate 6 (\ i -> [mk_rand_array ((i32.i64 i)+seeds[0]) 5 5])
  let C1_b : [6][28][28]f64 = tabulate 6 (\ i -> mk_rand_array ((i32.i64 i)+seeds[1]) 28 28)
  let C3_w : [16][6][5][5]f64 = tabulate 16 (\ i -> tabulate 6 (\ j -> mk_rand_array ((i32.i64 j)+seeds[2]+seeds[10+i]) 5 5))
  let C3_b : [16][10][10]f64 = tabulate 16 (\ i -> mk_rand_array ((i32.i64 i)+seeds[3]) 10 10)
  let t_w1 : [6][32]f64 = mk_rand_array seeds[4] 6 32 :> [6][32]f64
  let t_b1 : [6]f64 = flatten (mk_rand_array seeds[5] 1 6) :> [6]f64
  let t_w2 : [16][32]f64 = mk_rand_array seeds[4] 16 32 :> [16][32]f64
  let t_b2 : [16]f64 = flatten (mk_rand_array seeds[5] 1 16) :> [16]f64
  let F7_w : [784][400]f64 = mk_rand_array seeds[6] 784 400 :> [784][400]f64
  let F7_b : [784]f64 = flatten (mk_rand_array seeds[7] 1 784) :> [784]f64
  let F8_w : [5][84]f64 = mk_rand_array seeds[8] 5 84 :> [5][84]f64
  let F8_b : [5]f64 = flatten (mk_rand_array seeds[9] 1 5) :> [5]f64
  let weights_init = (C1_w,C1_b,C3_w,C3_b,t_w1,t_b1,t_w2,t_b2,F7_w,F7_b)


  in pred_diffu weights_init some_x_train[0]

