"""Optimized preparation and local SGD preserve the existing numeric contract."""
import numpy as np
import pytest

from dgfl.training import data, model


def _rectangle_means(images,grid):
    expected=np.empty((len(images),grid,grid),dtype=np.float64)
    for row in range(grid):
        top,bottom=row*28//grid,((row+1)*28+grid-1)//grid
        for column in range(grid):
            left,right=column*28//grid,((column+1)*28+grid-1)//grid
            expected[:,row,column]=images[:,top:bottom,left:right].mean(axis=(1,2))
    return expected.reshape(len(images),grid*grid)/255.0


@pytest.mark.parametrize('grid',range(1,29))
def test_uint8_pool_is_bit_exact_for_every_grid_and_noncontiguous_pixels(grid):
    images=np.random.default_rng(91).integers(0,256,(7,28,28),dtype=np.uint8)
    images[0]=0; images[1]=255
    images=images[:,::-1,::-1]
    saved=images.copy()
    np.testing.assert_array_equal(data._pool(images,grid),_rectangle_means(images,grid))
    np.testing.assert_array_equal(images,saved)


def test_pool_many_samples_and_float_inputs_keep_original_means():
    images=np.random.default_rng(3).integers(0,256,(1027,28,28),dtype=np.uint8)
    np.testing.assert_array_equal(data._pool(images,8),_rectangle_means(images,8))
    floats=np.random.default_rng(4).normal(size=(5,28,28))
    np.testing.assert_array_equal(data._pool(floats,13),_rectangle_means(floats,13))


def _original_numpy_sgd(weights,x,y,*,epochs,batch_size,seed,learning_rate,features):
    """Frozen arithmetic reference: separate exponent buffer and batch indices."""
    result=weights.copy(); split=features*10
    matrix,bias=result[:split].reshape(features,10),result[split:]
    generator=np.random.default_rng(seed)
    for _ in range(epochs):
        order=generator.permutation(len(y))
        for first in range(0,len(y),batch_size):
            indices=order[first:first+batch_size]; bx,by=x[indices],y[indices]
            logits=bx@matrix+bias
            logits-=logits.max(axis=1,keepdims=True)
            error=np.exp(logits)
            error/=error.sum(axis=1,keepdims=True)
            error[np.arange(len(by)),by]-=1
            error/=len(by)
            matrix-=learning_rate*(bx.T@error)
            bias-=learning_rate*error.sum(axis=0)
    return result


@pytest.mark.parametrize('features',[16,64,784])
@pytest.mark.parametrize('batch_size',[1,7,64])
def test_numpy_training_matches_original_full_vector_across_round_seeds(features,batch_size):
    generator=np.random.default_rng(5)
    x=generator.normal(size=(23,features)); y=generator.integers(0,10,23)
    weights=model.initial_model(7,features=features)
    x_saved,y_saved=x.copy(),y.copy()
    original=weights.copy()
    for seed in (41,42,43):
        options=dict(features=features,epochs=2,batch_size=batch_size,seed=seed,learning_rate=.03)
        original=_original_numpy_sgd(original,x,y,**options)
        weights=model.train_local(weights,x,y,**options)
        np.testing.assert_array_equal(weights,original)
    np.testing.assert_array_equal(x,x_saved); np.testing.assert_array_equal(y,y_saved)


def test_torch_batch_conversion_keeps_exact_original_torch_updates():
    torch=pytest.importorskip('torch')
    generator=np.random.default_rng(19)
    x=generator.normal(size=(17,64)); y=generator.integers(0,10,17)
    weights=model.initial_model(9)
    for seed in (21,22):
        tensor=torch.tensor(weights,dtype=torch.float64,requires_grad=True)
        features=torch.tensor(x,dtype=torch.float64); labels=torch.tensor(y,dtype=torch.int64)
        shuffle=np.random.default_rng(seed)
        for _ in range(2):
            order=shuffle.permutation(len(y))
            for first in range(0,len(y),7):
                indices=torch.tensor(order[first:first+7],dtype=torch.int64)
                logits=features[indices]@tensor[:640].reshape(64,10)+tensor[640:]
                torch.nn.functional.cross_entropy(logits,labels[indices]).backward()
                with torch.no_grad(): tensor-=.03*tensor.grad
                tensor.grad=None
        expected=tensor.detach().numpy().copy()
        weights=model.train_local(weights,x,y,epochs=2,batch_size=7,seed=seed,
                                  learning_rate=.03,backend='torch')
        np.testing.assert_array_equal(weights,expected)


@pytest.mark.parametrize('label_dtype',[np.uint8,np.int64])
def test_standalone_cnn_label_preparation_preserves_every_parameter(label_dtype):
    torch=pytest.importorskip('torch')
    from dgfl.training import paper_models as pm

    name='paper_cnn_mnist'; reference=pm.build_model(name,seed=11)
    initial=pm.flatten_parameters(reference)
    architecture=pm.model_manifest(reference)['architecture_hash']
    x=np.random.default_rng(3).random((5,1,28,28),dtype=np.float32)
    y=np.arange(5,dtype=label_dtype); saved_x,saved_y=x.copy(),y.copy()
    shuffle=np.random.default_rng(11)
    optimizer=torch.optim.SGD(reference.parameters(),lr=.01)
    reference.train()
    for _ in range(2):
        order=shuffle.permutation(len(y))
        for first in range(0,len(y),2):
            indices=order[first:first+2]
            samples=torch.from_numpy(np.ascontiguousarray(x[indices]))
            labels=torch.from_numpy(y[indices].astype(np.int64,copy=True))
            optimizer.zero_grad(set_to_none=True)
            torch.nn.functional.cross_entropy(reference(samples),labels).backward()
            optimizer.step()
    actual=pm.train_local(name,initial,architecture_hash=architecture,x=x,y=y,
                          epochs=2,batch_size=2,seed=11)
    np.testing.assert_array_equal(actual,pm.flatten_parameters(reference))
    np.testing.assert_array_equal(x,saved_x); np.testing.assert_array_equal(y,saved_y)
