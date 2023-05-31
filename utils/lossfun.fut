-- MSE_LOSS
def mse [n] (y_true : [n]f64) (y_pred : [n]f64) =
  (reduce (+) 0 (map2 (\t p -> (t - p)**2) y_true y_pred)) / (f64.i64 n)

def mse_prime [n] (y_true : [n]f64) (y_pred : [n]f64) =
  map2 (\ t p -> 2f64*(p-t) / (f64.i64 n)) y_true y_pred

def mse_loss_img [n][m] (y_true : [n][m]f64) (y_pred : [n][m]f64) =
  let sum = f64.sum (map2 (\ y x -> mse y x) y_true y_pred)
  in sum / f64.i64 n

let mse_loss_img_prime [n][m] (y_true : [n][m]f64) (y_pred : [n][m]f64) : [n][m]f64 =
  map2 (map2 (\ t p -> 2f64*(p-t) / (f64.i64 (n*m)))) y_true y_pred