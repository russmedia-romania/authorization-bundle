<?php

namespace RMT\AuthorizationBundle\Interfaces;

interface SecuredInterface
{
    public static function getSecurityKey(): string;
}