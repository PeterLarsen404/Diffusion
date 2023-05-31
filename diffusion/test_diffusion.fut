import "diffusion"
import "../gen_random/mk_random"
import "../utils/optimizers"

--
-- ==
-- entry: diffusion_train
-- compiled input @ ../datasets/diffusion/train_e1.in
-- auto output

--
-- ==
-- entry: diffusion_train
-- compiled input @ ../datasets/diffusion/train_e2.in
-- auto output

--
-- ==
-- entry: diffusion_train
-- compiled input @ ../datasets/diffusion/train_e3.in
-- auto output

--
-- ==
-- entry: diffusion_sample
-- compiled input @ ../datasets/diffusion/sample_1.in
-- auto output

--
-- ==
-- entry: diffusion_sample
-- compiled input @ ../datasets/diffusion/sample_2.in
-- auto output

--
-- ==
-- entry: diffusion_sample
-- compiled input @ ../datasets/diffusion/sample_3.in
-- auto output

--
-- COMPILE ERROR
-- entry: diffusion_ad
-- compiled input @ ../datasets/diffusion/test_e1.in
-- auto output

--
-- NOT DONE
-- entry: diffusion_generate_MNIST
-- compiled input @ ../datasets/diffusion/test_e1.in
-- auto output

let seed = 82i32
let initial_weights = mk_unet_wandb seed
let initial_adam = mk_initial_adam ()

entry diffusion_train [l][m][n] (images : [l][m][n]f64) (alpha_bar : []f64) (epochs : i64) (time_seeds : [epochs][l]i32) (noise_seeds : [epochs][l]i32) =
  let (trained_weights,losses) = train_unet images alpha_bar 32 epochs time_seeds noise_seeds (copy initial_weights) (copy initial_adam)
  in losses

entry diffusion_sample (num_imgs : i64) (beta : []f64) (alpha : []f64) (alpha_bar : []f64) (x_seed : i32) (eps_seed : i32) (denoise_steps : i64) =
  let sampled_imgs = sample num_imgs 32 x_seed eps_seed 28 denoise_steps beta alpha alpha_bar (copy initial_weights)
  in sampled_imgs

--entry diffusion_ad [l][m][n] (images : [l][m][n]f64) (epochs : i64) =
 -- let imgs = images[:1]
 -- let trained_weights = train_unet_ad imgs (copy alpha_bar) num_groups epochs (copy time_seeds) (copy noise_seeds) (copy initial_weights) (copy initial_adam)
 -- in (trained_weights.0).0

--entry diffusion_generate_MNIST [l][m][n] (images : [l][m][n]f64) =
 -- let train_dataset = images[:30]
 -- let epochs = 1000
 -- let seed = 42i32
 -- in ddpm_diffusion train_dataset epochs 1 seed