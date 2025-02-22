<?php
namespace App\DataFixtures;

use App\Entity\User;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Persistence\ObjectManager;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class AppFixtures extends Fixture
{
    private UserPasswordHasherInterface $passwordHasher;

    public function __construct(UserPasswordHasherInterface $passwordHasher)
    {
        $this->passwordHasher = $passwordHasher;
    }

    public function load(ObjectManager $manager): void
    {
        // Check if an admin user already exists
        $existingAdmin = $manager->getRepository(User::class)->findOneBy(['email' => 'admin@example.com']);

        if (!$existingAdmin) {
            $admin = new User();
            $admin->setEmail('edwinjones.m@gmail.com');
            $admin->setUsername('Edwin');
            $admin->setRoles(['ROLE_ADMIN']);
            $admin->setPassword($this->passwordHasher->hashPassword($admin, 'password1234'));
            $admin->setIsVerified(true); // ✅ Always verified

            $manager->persist($admin);
            $manager->flush();

            echo "✅ Admin user created successfully and is verified!\n";
        } else {
            // Update the admin to ensure it's always verified
            $existingAdmin->setIsVerified(true);
            $manager->persist($existingAdmin);
            $manager->flush();

            echo "⚠️ Admin user already exists. Ensured it is verified.\n";
        }
    }
}
