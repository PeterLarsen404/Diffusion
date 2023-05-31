import "../gen_random/mk_random"
import "../unet/unet"
import "../utils/lossfun"
import "../utils/optimizers"

def sinusoidal_position_embeddings (dim : i64) (t : f64) : [dim]f64 =
  let half_dim = f64.floor ((f64.i64 dim) / 2)
  let emb = (f64.log 10000) / (half_dim-1)
  let emb_arr = tabulate (i64.f64 half_dim) (\ i -> (f64.exp((f64.i64 i)*(-emb)))*t)
  let emb_sin_cos = map (\ x -> (f64.sin x, f64.cos x)) emb_arr
  let (emb_sin, emb_cos) = unzip emb_sin_cos
  in emb_sin ++ emb_cos :> [dim]f64

def mk_beta (steps : i64) (start : f64) (stop: f64) : [steps]f64 =
  tabulate steps (\i -> start+(f64.i64 i)*((stop-start)/((f64.i64 steps)-1f64)))

def mk_alpha [n] (betas : [n]f64) : [n]f64 =
  map (\b -> 1f64 - b) betas

def mk_alpha_bar [n] (alphas : [n]f64) : [n]f64 =
  scan (*) 1 alphas

def q_sample [n][m] (x0 : [n][m]f64) (t : i64) (alpha_bar : []f64) (seed : i32) : ([n][m]f64,[n][m]f64) =
  let mean = f64.sqrt alpha_bar[t]
  let var = 1f64 - alpha_bar[t]
  let eps = mk_rand_array seed n m
  let noisy_img = map2 (map2 (\ i e -> (i * mean) + (e * (f64.sqrt var)))) x0 eps
  in (noisy_img, eps)


def train_unet [l][n][m] (images : [l][n][m]f64) (alpha_bar : []f64) (num_groups : i64) (epochs : i64) (time_seeds : [][]i32) (noise_seeds : [][]i32) (initial_weights) (initial_adam) =
-- LOOP EPOCHS e in EPOCS
  let (trained_weights,_,losses) = loop (w_epochs,adam_epochs,losses_arr) = (initial_weights, initial_adam, []) for e < epochs do
     --LOOP IMAGES i in IMAGES
    let (w_out,adam_out,cum_loss) = loop (w_images,adam_images, cum_loss_) = (w_epochs,adam_epochs, 0f64) for i < l do
      let t = mk_rand_int time_seeds[e,i] 1 999 -- time_seeds skal være ret s$
      let (x_t, noise) = q_sample images[i] t alpha_bar noise_seeds[e,i]
      let time_embedding = sinusoidal_position_embeddings 256 (f64.i64 t) :> [256]f64
      let (predicted_noise, cache) = unet_simple x_t time_embedding num_groups w_images
      let loss = mse_loss_img noise predicted_noise
      let gradients = unet_simple_reverse x_t predicted_noise noise w_images cache
      let (new_weights,adam_cache) = adam_unet (e*l+i+1) 0.0003f64 0.9f64 0.999f64 1.0e-8f64 w_images gradients adam_images
      in (new_weights,adam_cache,cum_loss_+loss)
    let avg_loss = cum_loss / (f64.i64 l)
    in (w_out,adam_out,losses_arr++[avg_loss])
  in (trained_weights,losses)


def train_unet_ad [l][n][m] (images : [l][n][m]f64) (alpha_bar : []f64) (num_groups : i64) (epochs : i64) (time_seeds : [][]i32) (noise_seeds : [][]i32) (initial_weights) (initial_adam) =
-- LOOP EPOCHS e in EPOCS
  let (trained_weights,_) = loop (w_epochs,adam_epochs) = (initial_weights, initial_adam) for e < epochs do
     --LOOP IMAGES i in IMAGES
    let (w_out,adam_out) = loop (w_images,adam_images) = (w_epochs,adam_epochs) for i < l do
      let t = mk_rand_int time_seeds[e,i] 1 999
      let (x_t, noise) = q_sample images[i] t alpha_bar noise_seeds[e,i]
      let time_embedding = sinusoidal_position_embeddings 256 (f64.i64 t) :> [256]f64
      let loss w_images = mse_loss_img noise (unet_simple x_t time_embedding num_groups w_images).0
      let gradients = vjp loss w_images 1f64
      let (new_weights,adam_cache) = adam_unet (e*l+i+1) 0.0003f64 0.9f64 0.999f64 1.0e-8f64 w_images gradients adam_images
      in (new_weights,adam_cache)
    in (w_out,adam_out)
  in trained_weights

def p_sample [n][m][a] (x_t : [n][m]f64) (t : i64) (num_groups : i64) (beta : [a]f64) (alpha : [a]f64) (alpha_bar : [a]f64) (w_images) (seed: i32) : [n][m]f64 =
  let time_embedding = sinusoidal_position_embeddings 256 (f64.i64 t) :> [256]f64
  let (eps_theta,_) = unet_simple x_t time_embedding num_groups w_images

  let alpha_bar_t = alpha_bar[t]
  let alpha_t = alpha[t]
  let eps_coef = (1f64-alpha_t) / (f64.sqrt (1 - alpha_bar_t))
  let var = beta[t]

  let eps = if t > 1 then mk_rand_array seed n m else replicate n (replicate m 0f64)

  let res = map3 (map3 (\ xt eps_th e ->
    let mean = 1f64 / (f64.sqrt alpha_t) * (xt - eps_coef * eps_th)
    in mean + (f64.sqrt var) * e
    )) x_t eps_theta eps
  in res

def sample [a] (num_samples : i64) (num_groups : i64) (x_seed : i32) (eps_seed : i32) (img_size : i64) (n_steps : i64) (beta : [a]f64) (alpha : [a]f64) (alpha_bar : [a]f64) (trained_weights) =
  let noise_imgs_seeds = mk_rand_seeds x_seed num_samples
  let noise_imgs = map (\ x -> mk_rand_array x img_size img_size) noise_imgs_seeds
  let eps_seeds = mk_rand_seeds eps_seed n_steps
  let eps_seeds2d = map (\ x -> mk_rand_seeds x num_samples) eps_seeds
  let generated_imgs = loop denoised_imgs = noise_imgs for t_ < n_steps do
      let t = n_steps - t_ - 1i64
      let new_denoised_imgs = tabulate num_samples (\ i -> p_sample denoised_imgs[i] t num_groups beta alpha alpha_bar trained_weights eps_seeds2d[t_,i])
      in new_denoised_imgs
  in map (\ x ->
    let max = f64.maximum (flatten x)
    let min = f64.minimum (flatten x)
    in map (map (\ x -> ((x-min) / (max - min)) * (1-(-1))+(-1))) x
  ) generated_imgs


def ddpm_diffusion [l][m][n] (train_dataset : [l][m][n]f64) (epochs : i64) (gen_img_num : i64) (seed : i32) =
  let seeds = mk_rand_seeds seed 5
  let time_seeds = tabulate epochs (\ x -> mk_rand_seeds ((i32.i64 x)+seeds[0]) l)
  let noise_seeds = tabulate epochs (\ x -> mk_rand_seeds ((i32.i64 x)+seeds[1]) l)

  let beta = mk_beta 1000 0.0001 0.02
  let alpha = mk_alpha beta
  let alpha_bar = mk_alpha_bar alpha

  let initial_weights = mk_unet_wandb seeds[2]
  let initial_adam = mk_initial_adam ()
  let num_groups = 32i64 -- Only tested for 32.

  let (trained_weights,losses) = train_unet train_dataset alpha_bar num_groups epochs time_seeds noise_seeds initial_weights initial_adam

  let sampled_imgs = sample gen_img_num num_groups seeds[3] seeds[4] m 1000 beta alpha alpha_bar trained_weights
  in (losses,sampled_imgs,trained_weights)

