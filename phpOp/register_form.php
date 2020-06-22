<?php

return [
    [
        'name' => 'email',
        'type' => 'email',
        'message' => 'A valid e-mail address is required.',
        'attr' => "autofocus",
        'rules' => [
            'required' => true,
            'minlength' => 2,
            'maxlength' => 255
        ]
    ],
    [
        'name' => 'given_name',
        'type' => 'text',
        'attr' => "required",
        'message' => 'A given name is required.',
        'rules' => [
            'required' => true,
            'minlength' => 2,
            'maxlength' => 255
        ]
    ],
    [
        'name' => 'family_name',
        'type' => 'text',
        'attr' => "required",
        'message' => 'A family name is required.',
        'rules' => [
            'required' => true,
            'minlength' => 2,
            'maxlength' => 255
        ]
    ],
    [
        'name' => 'password',
        'type' => 'password',
        'message' => 'A complex password is required.',
        'attr' => "required data-eye",
        'rules' => [
            'required' => true,
            'minlength' => 2,
            'maxlength' => 255
        ]
    ],
    [
        'name' => 'login',
        'type' => 'computed',
        'rules' => [
            'equalTo' => 'email',
        ]
    ],
    [
        'name' => 'name',
        'type' => 'computed',
        'rules' => [
            'join' => ['given_name','family_name']
        ]
    ],
    [
        'name' => 'enabled',
        'type' => 'computed',
        'rules' => [
            'constant' => 1
        ]
    ]
];
