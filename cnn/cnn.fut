import "../lenet/lenet"
import "../utils/lossfun"
import "../utils/optimizers"

def train_lenet  [l][m][n] (images : [l][n][m]f64) (labels : [l][]f64) (epochs : i64) (inital_weights) =
  let (final_trained_weights, final_avg_losses) = loop (epoch_weights,epoch_losses) = (inital_weights,[]) for e < epochs do
    let (img_trained_weights, img_cum_losses) = loop (weights,losses) = (epoch_weights,0f64) for i < l do
      let (pred,cache) = (lenet_forward images[i] weights)
      let own_loss = mse labels[i] pred
      let own_grad = lenet_reverse images[i] pred labels[i] weights cache
      let new_weights = lenet_SGD own_grad weights
      in (new_weights,losses+own_loss)
    in (img_trained_weights, epoch_losses ++ [img_cum_losses / (f64.i64 l)])
  in (final_trained_weights, final_avg_losses)

def train_lenet_ad  [l][m][n] (images : [l][n][m]f64) (labels : [l][]f64) (epochs : i64) (inital_weights) =
  let (final_trained_weights, final_avg_losses) = loop (epoch_weights,epoch_losses) = (inital_weights,[]) for e < epochs do
    let (img_trained_weights, img_cum_losses) = loop (weights,losses) = (epoch_weights,0f64) for i < l do
      let loss weights = mse labels[i] (lenet_forward images[i] weights).0
      let grad_w = vjp loss weights 1f64
      let new_weights = lenet_SGD grad_w weights
      in (new_weights,losses)
    in (img_trained_weights, epoch_losses ++ [img_cum_losses / (f64.i64 l)])
  in (final_trained_weights, final_avg_losses)