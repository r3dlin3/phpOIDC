@extends('master')

@section('title')
@_e('TitleError')
@endsection

@section('content')
<div class="brand">
    <img src="{!! $site['theme_uri'] !!}/img/logo.png" alt="logo">
</div>
<div class="card fat text-white bg-danger">
    <div class="card-header">@_e('Error')</div>
    <div class="card-body">
        <h4 class="card-title">{{ $error }}</h4>
        <p class="card-text"> 
            {{ $desc }}
        </p>
    </div>
</div>
@endsection