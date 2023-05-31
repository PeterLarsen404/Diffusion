import "./linalg"

-- Sigmoid
def sigmoid (x : f64) =
  1/(1 + f64.exp (-x))

def sigmoid_b (out_grad : f64) (input : f64 ) =
  let s = sigmoid input
  in out_grad * (s * (1f64-s))

-- ReLU
def ReLU (x : f64) : f64 =
  f64.max 0f64 x

def ReLU_b (out_grad : f64) (input : f64) : f64 =
  if input > 0f64 then out_grad else 0f64

def ReLU_3d [o][n][m] (arr: [o][n][m]f64): [o][n][m]f64 =
  map (map (map ReLU)) arr

def ReLU_3d_b [o][n][m] (out_grad : [o][n][m]f64) (input : [o][n][m]f64) =
  map2 (map2 (map2 ReLU_b)) out_grad input

-- softmax
def softmax [n] (X : [n]f64) : [n]f64 =
  let X_exp = map f64.exp X
  let X_sum = f64.sum X_exp
  in map (\ x -> x / X_sum) X_exp

def softmax_b [m] (out_grad : [m]f64) (softmax_pred : [m]f64) : [m]f64 =
  let identity : [m][m]f64 = tabulate_2d m m (\ y x -> f64.bool (y==x))
  let id_diff = map (\ y -> map2 (-) y softmax_pred) identity
  let jac = map2 (\id pred -> map (\ x -> pred * x) id) id_diff softmax_pred
  let out_grad_2d = map (\x -> [x]) out_grad
  in flatten (matmul jac out_grad_2d) :> [m]f64


